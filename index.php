<?php
declare(strict_types=1);
session_start();

/* ============================================================
 * 1. БАЗА ДАННЫХ
 * ============================================================ */
$db = new PDO('sqlite:' . __DIR__ . '/hotel.db');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->exec('PRAGMA foreign_keys = ON');

$db->exec("
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'guest' CHECK(role IN ('guest','admin')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS room_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  capacity INTEGER NOT NULL CHECK(capacity > 0),
  price_per_night REAL NOT NULL CHECK(price_per_night >= 0)
);
CREATE TABLE IF NOT EXISTS rooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category_id INTEGER NOT NULL REFERENCES room_categories(id),
  room_number TEXT NOT NULL UNIQUE,
  floor INTEGER,
  status TEXT NOT NULL DEFAULT 'available' CHECK(status IN ('available','maintenance'))
);
CREATE TABLE IF NOT EXISTS bookings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  room_id INTEGER NOT NULL REFERENCES rooms(id),
  check_in TEXT NOT NULL,
  check_out TEXT NOT NULL,
  guests_count INTEGER NOT NULL CHECK(guests_count > 0),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','cancelled')),
  admin_comment TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK(check_out > check_in)
);
");

/* Сиды при первом запуске */
if ((int)$db->query("SELECT COUNT(*) FROM users")->fetchColumn() === 0) {
    $db->prepare("INSERT INTO users (email,password_hash,full_name,phone,role) VALUES (?,?,?,?,?)")
       ->execute(['admin@sweetdreams.ru', password_hash('admin123', PASSWORD_DEFAULT), 'Администратор', '+70000000000', 'admin']);

    $cats = [
        ['Стандарт', 'Уютный номер с двуспальной кроватью, кондиционером и рабочим столом.', 2, 3500],
        ['Комфорт',  'Просторный номер с видом на парк, мини-баром и ванной с душем.',       3, 5500],
        ['Люкс',     'Двухкомнатный номер с гостиной, панорамными окнами и джакузи.',        4, 9000],
        ['Семейный', 'Номер для всей семьи с двумя спальнями и кухонной зоной.',             5, 7500],
    ];
    $stmt = $db->prepare("INSERT INTO room_categories (name,description,capacity,price_per_night) VALUES (?,?,?,?)");
    foreach ($cats as $c) $stmt->execute($c);

    $rooms = [
        [1,'101',1],[1,'102',1],[1,'103',1],
        [2,'201',2],[2,'202',2],[2,'203',2],
        [3,'301',3],[3,'302',3],
        [4,'401',4],[4,'402',4],
    ];
    $stmt = $db->prepare("INSERT INTO rooms (category_id,room_number,floor) VALUES (?,?,?)");
    foreach ($rooms as $r) $stmt->execute($r);
}

/* ============================================================
 * 2. ХЕЛПЕРЫ
 * ============================================================ */
function e($v): string { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
function redirect(string $url): never { header("Location: $url"); exit; }
function csrf_token(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function csrf_check(): void {
    if (empty($_POST['csrf']) || !hash_equals($_SESSION['csrf'] ?? '', (string)$_POST['csrf'])) {
        http_response_code(403);
        exit('Недействительный CSRF-токен. Обновите страницу.');
    }
}
function current_user(PDO $db): ?array {
    if (empty($_SESSION['user_id'])) return null;
    $s = $db->prepare("SELECT id,email,full_name,role FROM users WHERE id=?");
    $s->execute([(int)$_SESSION['user_id']]);
    return $s->fetch() ?: null;
}
function valid_date(?string $s): bool {
    if (!$s) return false;
    $d = DateTimeImmutable::createFromFormat('Y-m-d', $s);
    return $d && $d->format('Y-m-d') === $s;
}

/* ============================================================
 * 3. СОСТОЯНИЕ
 * ============================================================ */
$errors  = [];
$success = '';
$page    = $_GET['page'] ?? 'home';
$user    = current_user($db);

/* ============================================================
 * 4. ОБРАБОТКА POST
 * ============================================================ */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = $_POST['action'] ?? '';

    /* --- Регистрация --- */
    if ($action === 'register') {
        $email = trim((string)($_POST['email'] ?? ''));
        $name  = trim((string)($_POST['full_name'] ?? ''));
        $phone = trim((string)($_POST['phone'] ?? ''));
        $pwd   = (string)($_POST['password'] ?? '');
        $pwd2  = (string)($_POST['password2'] ?? '');

        if (!filter_var($email, FILTER_VALIDATE_EMAIL))       $errors[] = 'Введите корректный e-mail.';
        if (mb_strlen($name) < 2)                             $errors[] = 'Укажите полное имя (минимум 2 символа).';
        if (!preg_match('/^\+?[0-9 ()\-]{7,20}$/', $phone))   $errors[] = 'Введите корректный телефон.';
        if (strlen($pwd) < 6)                                 $errors[] = 'Пароль должен быть не короче 6 символов.';
        if ($pwd !== $pwd2)                                   $errors[] = 'Пароли не совпадают.';

        if (!$errors) {
            try {
                $db->prepare("INSERT INTO users (email,password_hash,full_name,phone) VALUES (?,?,?,?)")
                   ->execute([$email, password_hash($pwd, PASSWORD_DEFAULT), $name, $phone]);
                $_SESSION['user_id'] = (int)$db->lastInsertId();
                $_SESSION['flash'] = 'Регистрация успешна. Добро пожаловать!';
                redirect('?page=home');
            } catch (PDOException $ex) {
                $errors[] = 'Этот e-mail уже зарегистрирован.';
            }
        }
        $page = 'register';
    }

    /* --- Вход --- */
    elseif ($action === 'login') {
        $email = trim((string)($_POST['email'] ?? ''));
        $pwd   = (string)($_POST['password'] ?? '');
        $s = $db->prepare("SELECT * FROM users WHERE email=?");
        $s->execute([$email]);
        $u = $s->fetch();
        if (!$u || !password_verify($pwd, $u['password_hash'])) {
            $errors[] = 'Неверный e-mail или пароль.';
            $page = 'login';
        } else {
            session_regenerate_id(true);
            $_SESSION['user_id'] = (int)$u['id'];
            redirect($u['role'] === 'admin' ? '?page=admin_bookings' : '?page=my_bookings');
        }
    }

    /* --- Бронирование --- */
    elseif ($action === 'book') {
        if (!$user) {
            $errors[] = 'Требуется вход в систему.';
            $page = 'login';
        } else {
            $roomId   = filter_var($_POST['room_id'] ?? '', FILTER_VALIDATE_INT);
            $checkIn  = (string)($_POST['check_in'] ?? '');
            $checkOut = (string)($_POST['check_out'] ?? '');
            $guests   = filter_var($_POST['guests'] ?? '', FILTER_VALIDATE_INT,
                                   ['options'=>['min_range'=>1,'max_range'=>10]]);
            $today = (new DateTimeImmutable('today'))->format('Y-m-d');

            if (!valid_date($checkIn))                $errors[] = 'Некорректная дата заезда.';
            elseif ($checkIn < $today)                $errors[] = 'Дата заезда не может быть в прошлом.';
            if (!valid_date($checkOut))               $errors[] = 'Некорректная дата выезда.';
            elseif (valid_date($checkIn) && $checkOut <= $checkIn)
                $errors[] = 'Дата выезда должна быть позже даты заезда.';
            elseif (valid_date($checkIn) &&
                    (new DateTimeImmutable($checkIn))->diff(new DateTimeImmutable($checkOut))->days > 30)
                $errors[] = 'Максимальный срок — 30 ночей.';
            if ($guests === false)                    $errors[] = 'Укажите число гостей от 1 до 10.';
            if (!$roomId)                             $errors[] = 'Выберите номер.';

            if (!$errors) {
                $s = $db->prepare("SELECT r.status, rc.capacity FROM rooms r
                                   JOIN room_categories rc ON rc.id=r.category_id WHERE r.id=?");
                $s->execute([$roomId]);
                $info = $s->fetch();
                if (!$info || $info['status'] !== 'available')
                    $errors[] = 'Номер недоступен.';
                elseif ($guests > (int)$info['capacity'])
                    $errors[] = "Номер вмещает не более {$info['capacity']} гостей.";
            }

            if (!$errors) {
                $db->beginTransaction();
                try {
                    $s = $db->prepare("SELECT 1 FROM bookings
                                       WHERE room_id=? AND status IN ('pending','approved')
                                         AND check_in < ? AND check_out > ? LIMIT 1");
                    $s->execute([$roomId, $checkOut, $checkIn]);
                    if ($s->fetch())
                        throw new RuntimeException('Номер уже занят на выбранные даты.');
                    $db->prepare("INSERT INTO bookings (user_id,room_id,check_in,check_out,guests_count)
                                  VALUES (?,?,?,?,?)")
                       ->execute([(int)$user['id'], $roomId, $checkIn, $checkOut, $guests]);
                    $db->commit();
                    $_SESSION['flash'] = 'Заявка отправлена на модерацию!';
                    redirect('?page=my_bookings');
                } catch (Throwable $ex) {
                    $db->rollBack();
                    $errors[] = $ex->getMessage();
                }
            }
            $page = 'home';
        }
    }

    /* --- Модерация (только админ) --- */
    elseif ($action === 'moderate') {
        if (!$user || $user['role'] !== 'admin') {
            http_response_code(403);
            exit('Доступ запрещён.');
        }
        $id       = filter_var($_POST['booking_id'] ?? '', FILTER_VALIDATE_INT);
        $decision = (string)($_POST['decision'] ?? '');
        $comment  = trim((string)($_POST['comment'] ?? ''));

        if (!$id || !in_array($decision, ['approved','rejected'], true)) {
            $errors[] = 'Некорректные данные модерации.';
        } else {
            $s = $db->prepare("UPDATE bookings SET status=?, admin_comment=?
                               WHERE id=? AND status='pending'");
            $s->execute([$decision, $comment !== '' ? $comment : null, $id]);
            if ($s->rowCount() === 0)
                $errors[] = 'Заявка не найдена или уже обработана.';
            else {
                $_SESSION['flash'] = 'Заявка обновлена.';
                redirect('?page=admin_bookings');
            }
        }
        $page = 'admin_bookings';
    }

    /* --- Отмена гостем --- */
    elseif ($action === 'cancel') {
        if (!$user) { http_response_code(403); exit('Доступ запрещён.'); }
        $id = filter_var($_POST['booking_id'] ?? '', FILTER_VALIDATE_INT);
        if ($id) {
            $s = $db->prepare("UPDATE bookings SET status='cancelled'
                               WHERE id=? AND user_id=? AND status='pending'");
            $s->execute([$id, (int)$user['id']]);
            $_SESSION['flash'] = $s->rowCount() ? 'Заявка отменена.' : 'Отмена невозможна.';
        }
        redirect('?page=my_bookings');
    }
}

/* Выход */
if ($page === 'logout') {
    session_destroy();
    redirect('?page=home');
}

/* Защита страниц */
if ($page === 'my_bookings' && !$user) redirect('?page=login');
if ($page === 'admin_bookings' && (!$user || $user['role'] !== 'admin')) {
    $_SESSION['flash'] = 'Доступ только для администратора.';
    redirect('?page=home');
}

/* Флеш-сообщение */
if (empty($success) && !empty($_SESSION['flash'])) {
    $success = (string)$_SESSION['flash'];
    unset($_SESSION['flash']);
}

/* ============================================================
 * 5. ДАННЫЕ ДЛЯ СТРАНИЦ
 * ============================================================ */
$STATUS_LABELS = [
    'pending'   => 'На модерации',
    'approved'  => 'Одобрена',
    'rejected'  => 'Отклонена',
    'cancelled' => 'Отменена',
];

$categories = $db->query("SELECT * FROM room_categories ORDER BY price_per_night")->fetchAll();

if ($page === 'home') {
    $f_check_in  = (string)($_GET['check_in'] ?? '');
    $f_check_out = (string)($_GET['check_out'] ?? '');
    $f_guests    = max(1, (int)($_GET['guests'] ?? 1));
    $f_min       = $_GET['min_price'] ?? '';
    $f_max       = $_GET['max_price'] ?? '';
    $f_cat       = (int)($_GET['category'] ?? 0);

    $dates_ok = valid_date($f_check_in) && valid_date($f_check_out) && $f_check_out > $f_check_in;

    $sql = "SELECT r.id, r.room_number, r.floor, rc.name, rc.description,
                   rc.capacity, rc.price_per_night, rc.id AS cat_id
            FROM rooms r JOIN room_categories rc ON rc.id=r.category_id
            WHERE r.status='available'";
    $params = [];
    if ($f_guests > 0) { $sql .= " AND rc.capacity >= ?"; $params[] = $f_guests; }
    if ($f_min !== '' && is_numeric($f_min)) { $sql .= " AND rc.price_per_night >= ?"; $params[] = (float)$f_min; }
    if ($f_max !== '' && is_numeric($f_max)) { $sql .= " AND rc.price_per_night <= ?"; $params[] = (float)$f_max; }
    if ($f_cat > 0)    { $sql .= " AND rc.id = ?"; $params[] = $f_cat; }
    if ($dates_ok) {
        $sql .= " AND NOT EXISTS (
                    SELECT 1 FROM bookings b
                    WHERE b.room_id = r.id
                      AND b.status IN ('pending','approved')
                      AND b.check_in < ? AND b.check_out > ?
                  )";
        $params[] = $f_check_out;
        $params[] = $f_check_in;
    }
    $sql .= " ORDER BY rc.price_per_night, r.room_number";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rooms = $stmt->fetchAll();
}

if ($page === 'my_bookings' && $user) {
    $stmt = $db->prepare("
        SELECT b.*, r.room_number, rc.name AS cat_name, rc.price_per_night
        FROM bookings b
        JOIN rooms r ON r.id = b.room_id
        JOIN room_categories rc ON rc.id = r.category_id
        WHERE b.user_id = ?
        ORDER BY b.created_at DESC");
    $stmt->execute([(int)$user['id']]);
    $myBookings = $stmt->fetchAll();
}

if ($page === 'admin_bookings') {
    $statusFilter = (string)($_GET['status'] ?? 'pending');
    if (!in_array($statusFilter, ['pending','approved','rejected','cancelled','all'], true))
        $statusFilter = 'pending';

    $sql = "SELECT b.*, r.room_number, rc.name AS cat_name,
                   u.full_name AS guest_name, u.email AS guest_email, u.phone AS guest_phone
            FROM bookings b
            JOIN rooms r ON r.id = b.room_id
            JOIN room_categories rc ON rc.id = r.category_id
            JOIN users u ON u.id = b.user_id";
    $params = [];
    if ($statusFilter !== 'all') { $sql .= " WHERE b.status = ?"; $params[] = $statusFilter; }
    $sql .= " ORDER BY b.created_at DESC";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $allBookings = $stmt->fetchAll();
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Отель «Сладкие сны»</title>
<style>
:root{
  --primary:#6B5B95; --primary-dark:#4A3F6B; --accent:#D4AF37;
  --bg:#FAF6F0; --card:#FFFFFF; --text:#2C2A2E; --muted:#6B6870;
  --border:#E6E0D5; --danger:#B83A3A; --danger-bg:#FBEAEA;
  --success:#2F7A5B; --success-bg:#E7F4EE;
}
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
     background:var(--bg);color:var(--text);line-height:1.5;
     min-height:100vh;display:flex;flex-direction:column}
.container{max-width:1200px;margin:0 auto;padding:0 20px;width:100%}
header{background:var(--primary);color:#fff;padding:16px 0;
       box-shadow:0 2px 12px rgba(0,0,0,.08)}
.header-inner{display:flex;align-items:center;justify-content:space-between;
              gap:24px;flex-wrap:wrap}
.logo{color:#fff;text-decoration:none;font-size:22px;font-weight:700}
nav{display:flex;gap:20px;align-items:center;flex-wrap:wrap}
nav a{color:#fff;text-decoration:none;opacity:.9;font-size:15px}
nav a:hover{opacity:1;text-decoration:underline}
nav .user{color:var(--accent);font-weight:600}
main{flex:1;padding:32px 0}
footer{text-align:center;padding:24px;color:var(--muted);font-size:14px}
h1{margin-top:0;font-size:32px;color:var(--primary-dark)}
h2{color:var(--primary-dark)}

.alert{padding:14px 18px;border-radius:8px;margin-bottom:20px;border:1px solid}
.alert-success{background:var(--success-bg);color:var(--success);border-color:#BFE0D0}
.alert-danger{background:var(--danger-bg);color:var(--danger);border-color:#F0C6C6}
.alert ul{margin:0;padding-left:20px}

.filter-form{background:var(--card);padding:20px;border-radius:12px;
             border:1px solid var(--border);margin-bottom:28px;
             display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
             gap:14px;align-items:end}
.filter-form label{display:flex;flex-direction:column;font-size:13px;
                   color:var(--muted);gap:6px}
.filter-form input,.filter-form select{padding:10px 12px;border:1px solid var(--border);
  border-radius:8px;font-size:14px;background:#fff;color:var(--text);width:100%}

.rooms-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px}
.room-card{background:var(--card);border:1px solid var(--border);
           border-radius:14px;overflow:hidden;display:flex;flex-direction:column}
.room-card-body{padding:20px;flex:1;display:flex;flex-direction:column;gap:10px}
.room-card h3{margin:0;color:var(--primary-dark);font-size:20px}
.badge{display:inline-block;padding:3px 10px;background:#F0EBFF;
       color:var(--primary);border-radius:999px;font-size:12px;font-weight:600}
.price{margin-top:auto;font-size:20px;font-weight:700;color:var(--primary)}
.price small{font-size:13px;color:var(--muted);font-weight:400}
.desc{font-size:14px;color:var(--muted)}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;
     padding:10px 18px;border-radius:8px;border:1px solid transparent;
     background:var(--primary);color:#fff;font-size:14px;font-weight:600;
     cursor:pointer;text-decoration:none;transition:background .15s}
.btn:hover{background:var(--primary-dark)}
.btn-outline{background:transparent;color:var(--primary);border-color:var(--primary)}
.btn-outline:hover{background:var(--primary);color:#fff}
.btn-danger{background:var(--danger)}
.btn-danger:hover{background:#962D2D}
.btn-sm{padding:7px 12px;font-size:13px}

.auth-form{max-width:420px;margin:40px auto;background:var(--card);
           padding:30px;border-radius:12px;border:1px solid var(--border)}
.auth-form label{display:flex;flex-direction:column;gap:6px;font-size:13px;
                 color:var(--muted);margin-bottom:14px}
.auth-form input{padding:11px 14px;border:1px solid var(--border);
                 border-radius:8px;font-size:15px}
.auth-form .btn{width:100%;margin-top:8px}
.auth-form h1{margin-bottom:20px;font-size:26px}

.bookings-table{width:100%;border-collapse:collapse;background:var(--card);
                border-radius:12px;overflow:hidden;
                box-shadow:0 1px 4px rgba(0,0,0,.04)}
.bookings-table th,.bookings-table td{padding:12px 14px;text-align:left;
  font-size:14px;border-bottom:1px solid var(--border);vertical-align:top}
.bookings-table th{background:#F5F1EA;color:var(--primary-dark);
  font-weight:600;font-size:13px;text-transform:uppercase;letter-spacing:.4px}
.bookings-table tr:last-child td{border-bottom:none}

.status{display:inline-block;padding:3px 10px;border-radius:999px;
        font-size:12px;font-weight:600}
.status-pending{background:#FFF4D6;color:#8A6A00}
.status-approved{background:var(--success-bg);color:var(--success)}
.status-rejected{background:var(--danger-bg);color:var(--danger)}
.status-cancelled{background:#EEEEEE;color:#6B6870}

.moderate-form{display:flex;flex-direction:column;gap:8px;min-width:220px}
.moderate-form textarea{padding:8px;border:1px solid var(--border);
  border-radius:6px;font-family:inherit;font-size:13px;resize:vertical;min-height:44px}
.moderate-actions{display:flex;gap:6px}

.filters-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px;align-items:center}
.filters-row a{padding:6px 14px;border-radius:999px;border:1px solid var(--border);
  background:var(--card);color:var(--text);text-decoration:none;font-size:13px}
.filters-row a.active{background:var(--primary);color:#fff;border-color:var(--primary)}

.empty{text-align:center;padding:60px 20px;color:var(--muted)}
.admin-info{background:#FFF9E6;border:1px solid #F0E0A0;padding:12px 16px;
            border-radius:8px;margin-bottom:20px;font-size:13px;color:#6E5800}
</style>
</head>
<body>

<header>
  <div class="container header-inner">
    <a href="?page=home" class="logo">🌙 Сладкие сны</a>
    <nav>
      <a href="?page=home">Номера</a>
      <?php if ($user): ?>
        <a href="?page=my_bookings">Мои заявки</a>
        <?php if ($user['role'] === 'admin'): ?>
          <a href="?page=admin_bookings">Модерация</a>
        <?php endif; ?>
        <span class="user"><?= e($user['full_name']) ?></span>
        <a href="?page=logout">Выйти</a>
      <?php else: ?>
        <a href="?page=login">Вход</a>
        <a href="?page=register">Регистрация</a>
      <?php endif; ?>
    </nav>
  </div>
</header>

<main>
<div class="container">

<?php if ($success): ?>
  <div class="alert alert-success"><?= e($success) ?></div>
<?php endif; ?>

<?php if ($errors): ?>
  <div class="alert alert-danger">
    <ul>
      <?php foreach ($errors as $err): ?><li><?= e($err) ?></li><?php endforeach; ?>
    </ul>
  </div>
<?php endif; ?>

<?php /* ============================= HOME ============================= */ ?>
<?php if ($page === 'home'): ?>
  <h1>Каталог номеров</h1>

  <form class="filter-form" method="get" action="">
    <input type="hidden" name="page" value="home">
    <label>Заезд
      <input type="date" name="check_in" value="<?= e($f_check_in ?? '') ?>">
    </label>
    <label>Выезд
      <input type="date" name="check_out" value="<?= e($f_check_out ?? '') ?>">
    </label>
    <label>Гостей
      <input type="number" name="guests" min="1" max="10" value="<?= (int)($f_guests ?? 1) ?>">
    </label>
    <label>Цена от, ₽
      <input type="number" name="min_price" min="0" step="100" value="<?= e($f_min ?? '') ?>">
    </label>
    <label>Цена до, ₽
      <input type="number" name="max_price" min="0" step="100" value="<?= e($f_max ?? '') ?>">
    </label>
    <label>Категория
      <select name="category">
        <option value="0">Все</option>
        <?php foreach ($categories as $c): ?>
          <option value="<?= (int)$c['id'] ?>" <?= ($f_cat ?? 0) == $c['id'] ? 'selected' : '' ?>>
            <?= e($c['name']) ?>
          </option>
        <?php endforeach; ?>
      </select>
    </label>
    <div>
      <button class="btn" type="submit">Найти</button>
      <a class="btn btn-outline" href="?page=home">Сбросить</a>
    </div>
  </form>

  <?php if ($dates_ok ?? false): ?>
    <p style="color:var(--muted);margin-top:-12px">
      Показаны номера, свободные с <?= e($f_check_in) ?> по <?= e($f_check_out) ?>.
    </p>
  <?php endif; ?>

  <?php if (empty($rooms)): ?>
    <div class="empty">По заданным условиям ничего не найдено. Попробуйте изменить фильтры.</div>
  <?php else: ?>
    <div class="rooms-grid">
      <?php foreach ($rooms as $r): ?>
        <div class="room-card">
          <div class="room-card-body">
            <span class="badge">до <?= (int)$r['capacity'] ?> гостей</span>
            <h3><?= e($r['name']) ?></h3>
            <div style="color:var(--muted);font-size:13px">
              Номер №<?= e($r['room_number']) ?> · <?= (int)$r['floor'] ?> этаж
            </div>
            <div class="desc"><?= e($r['description']) ?></div>
            <div class="price"><?= number_format((float)$r['price_per_night'], 0, '.', ' ') ?> ₽ <small>/ ночь</small></div>

            <?php if ($user): ?>
              <form method="post" action="?page=home">
                <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="book">
                <input type="hidden" name="room_id" value="<?= (int)$r['id'] ?>">
                <input type="hidden" name="check_in"  value="<?= e($f_check_in ?? '') ?>">
                <input type="hidden" name="check_out" value="<?= e($f_check_out ?? '') ?>">
                <input type="hidden" name="guests"    value="<?= (int)($f_guests ?? 1) ?>">
                <button class="btn" type="submit" style="width:100%">
                  Забронировать
                </button>
                <?php if (!($dates_ok ?? false)): ?>
                  <div style="font-size:12px;color:var(--muted);margin-top:8px">
                    Укажите даты в фильтре, чтобы забронировать.
                  </div>
                <?php endif; ?>
              </form>
            <?php else: ?>
              <a href="?page=login" class="btn btn-outline" style="width:100%">
                Войти для брони
              </a>
            <?php endif; ?>
          </div>
        </div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

<?php /* ============================= REGISTER ============================= */ ?>
<?php elseif ($page === 'register'): ?>
  <form class="auth-form" method="post" action="?page=register">
    <h1>Регистрация</h1>
    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <input type="hidden" name="action" value="register">
    <label>E-mail
      <input type="email" name="email" required value="<?= e($_POST['email'] ?? '') ?>">
    </label>
    <label>Полное имя
      <input type="text" name="full_name" required minlength="2" value="<?= e($_POST['full_name'] ?? '') ?>">
    </label>
    <label>Телефон
      <input type="tel" name="phone" required value="<?= e($_POST['phone'] ?? '') ?>">
    </label>
    <label>Пароль (не менее 6 символов)
      <input type="password" name="password" required minlength="6">
    </label>
    <label>Повтор пароля
      <input type="password" name="password2" required minlength="6">
    </label>
    <button class="btn" type="submit">Создать аккаунт</button>
  </form>

<?php /* ============================= LOGIN ============================= */ ?>
<?php elseif ($page === 'login'): ?>
  <form class="auth-form" method="post" action="?page=login">
    <h1>Вход</h1>
    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <input type="hidden" name="action" value="login">
    <label>E-mail
      <input type="email" name="email" required value="<?= e($_POST['email'] ?? '') ?>">
    </label>
    <label>Пароль
      <input type="password" name="password" required>
    </label>
    <button class="btn" type="submit">Войти</button>
  </form>

<?php /* ============================= MY BOOKINGS ============================= */ ?>
<?php elseif ($page === 'my_bookings'): ?>
  <h1>Мои заявки</h1>
  <?php if (empty($myBookings)): ?>
    <div class="empty">
      У вас пока нет заявок. <a href="?page=home">Перейти к каталогу</a>
    </div>
  <?php else: ?>
    <table class="bookings-table">
      <thead>
        <tr>
          <th>№</th><th>Номер</th><th>Даты</th><th>Гостей</th>
          <th>Сумма</th><th>Статус</th><th>Комментарий</th><th>Действия</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($myBookings as $b):
          $nights = (new DateTimeImmutable($b['check_in']))->diff(new DateTimeImmutable($b['check_out']))->days;
          $sum    = $nights * (float)$b['price_per_night'];
        ?>
        <tr>
          <td>#<?= (int)$b['id'] ?></td>
          <td>
            <?= e($b['cat_name']) ?><br>
            <small style="color:var(--muted)">№<?= e($b['room_number']) ?></small>
          </td>
          <td><?= e($b['check_in']) ?> → <?= e($b['check_out']) ?><br>
              <small style="color:var(--muted)"><?= $nights ?> ноч.</small></td>
          <td><?= (int)$b['guests_count'] ?></td>
          <td><?= number_format($sum, 0, '.', ' ') ?> ₽</td>
          <td>
            <span class="status status-<?= e($b['status']) ?>">
              <?= e($STATUS_LABELS[$b['status']] ?? $b['status']) ?>
            </span>
          </td>
          <td><?= e($b['admin_comment'] ?? '—') ?></td>
          <td>
            <?php if ($b['status'] === 'pending'): ?>
              <form method="post" action="?page=my_bookings" style="margin:0"
                    onsubmit="return confirm('Отменить заявку?')">
                <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="cancel">
                <input type="hidden" name="booking_id" value="<?= (int)$b['id'] ?>">
                <button class="btn btn-danger btn-sm" type="submit">Отменить</button>
              </form>
            <?php else: ?>
              —
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  <?php endif; ?>

<?php /* ============================= ADMIN ============================= */ ?>
<?php elseif ($page === 'admin_bookings'): ?>
  <h1>Модерация заявок</h1>
  <div class="admin-info">
    Все действия выполняются на стороне сервера. Статус «На модерации» можно
    одобрить или отклонить; решение фиксируется в БД.
  </div>

  <div class="filters-row">
    <?php foreach (['pending'=>'На модерации','approved'=>'Одобрены',
                    'rejected'=>'Отклонены','cancelled'=>'Отменены','all'=>'Все'] as $key=>$label): ?>
      <a href="?page=admin_bookings&status=<?= e($key) ?>"
         class="<?= $statusFilter === $key ? 'active' : '' ?>"><?= e($label) ?></a>
    <?php endforeach; ?>
  </div>

  <?php if (empty($allBookings)): ?>
    <div class="empty">Заявок в этой категории нет.</div>
  <?php else: ?>
    <table class="bookings-table">
      <thead>
        <tr>
          <th>№</th><th>Гость</th><th>Номер</th><th>Даты</th>
          <th>Гостей</th><th>Статус</th><th>Модерация</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($allBookings as $b): ?>
        <tr>
          <td>#<?= (int)$b['id'] ?><br>
              <small style="color:var(--muted)"><?= e($b['created_at']) ?></small>
          </td>
          <td>
            <?= e($b['guest_name']) ?><br>
            <small style="color:var(--muted)"><?= e($b['guest_email']) ?></small><br>
            <small style="color:var(--muted)"><?= e($b['guest_phone']) ?></small>
          </td>
          <td><?= e($b['cat_name']) ?><br>
              <small style="color:var(--muted)">№<?= e($b['room_number']) ?></small></td>
          <td><?= e($b['check_in']) ?> → <?= e($b['check_out']) ?></td>
          <td><?= (int)$b['guests_count'] ?></td>
          <td>
            <span class="status status-<?= e($b['status']) ?>">
              <?= e($STATUS_LABELS[$b['status']] ?? $b['status']) ?>
            </span>
            <?php if (!empty($b['admin_comment'])): ?>
              <div style="font-size:12px;color:var(--muted);margin-top:6px">
                <?= e($b['admin_comment']) ?>
              </div>
            <?php endif; ?>
          </td>
          <td>
            <?php if ($b['status'] === 'pending'): ?>
              <form class="moderate-form" method="post" action="?page=admin_bookings">
                <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="moderate">
                <input type="hidden" name="booking_id" value="<?= (int)$b['id'] ?>">
                <textarea name="comment" maxlength="500"
                          placeholder="Комментарий (необязательно)"></textarea>
                <div class="moderate-actions">
                  <button class="btn btn-sm" type="submit"
                          name="decision" value="approved">Одобрить</button>
                  <button class="btn btn-danger btn-sm" type="submit"
                          name="decision" value="rejected">Отклонить</button>
                </div>
              </form>
            <?php else: ?>
              <span style="color:var(--muted);font-size:13px">Обработана</span>
            <?php endif; ?>
          </td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  <?php endif; ?>

<?php endif; ?>

</div>
</main>

<footer>© <?= date('Y') ?> Отель «Сладкие сны»</footer>
</body>
</html>