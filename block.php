<?php
/**
 * Sucuri Enterprise whitelabel block page.
 * Each client hosts this on their origin; WAF custom block redirects here (often via /ipblocked).
 */
declare(strict_types=1);

function h(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function clientIp(): string
{
    if (!empty($_SERVER['HTTP_X_SUCURI_CLIENTIP'])) {
        return trim((string) $_SERVER['HTTP_X_SUCURI_CLIENTIP']);
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '');
}

function edgePop(): string
{
    // Prefer value passed from intercept redirect, e.g. block.php?edge=20012
    if (!empty($_GET['edge'])) {
        return preg_replace('/\D/', '', (string) $_GET['edge']);
    }
    if (!empty($_GET['sucuri_id'])) {
        return preg_replace('/\D/', '', (string) $_GET['sucuri_id']);
    }
    // May reflect this request's edge, not the 403 intercept — show only if present
    if (!empty($_SERVER['HTTP_X_SUCURI_ID'])) {
        return preg_replace('/\D/', '', (string) $_SERVER['HTTP_X_SUCURI_ID']);
    }
    return '';
}

function blockFlowReferer(): string
{
    return trim((string) ($_SERVER['HTTP_REFERER'] ?? ''));
}

function supportReference(string $ip, string $host): string
{
    $seed = $ip . '|' . $host . '|' . gmdate('Y-m-d H:i');
    return strtoupper(substr(hash('sha256', $seed), 0, 8));
}

$ip       = clientIp();
$country  = trim((string) ($_SERVER['HTTP_X_SUCURI_COUNTRY'] ?? ''));
$host     = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
$ua       = trim((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''));
$referer  = blockFlowReferer();
$edge     = edgePop();
$blockId  = trim((string) ($_GET['block'] ?? $_GET['bid'] ?? $_SERVER['HTTP_X_SUCURI_BLOCK'] ?? ''));

date_default_timezone_set('America/New_York');
$when = date('Y-m-d H:i:s T');
$ref  = supportReference($ip, $host);

$debug = isset($_GET['debug']) && $_GET['debug'] === '1';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Access blocked</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
    h1 { text-align: center; }
    .support { background: #f4f4f5; border-radius: 8px; padding: 1rem 1.25rem; margin: 1.5rem 0; font-size: 0.95rem; }
    .support dt { font-weight: 600; margin-top: 0.5rem; }
    .support dt:first-child { margin-top: 0; }
    .support dd { margin: 0.15rem 0 0 0; word-break: break-word; }
    .muted { color: #52525b; font-size: 0.9rem; text-align: center; }
    pre.debug { font-size: 11px; text-align: left; overflow: auto; }
  </style>
</head>
<body>
  <h1>⛔ <strong>You&rsquo;ve been blocked</strong> ⛔</h1>
  <p class="muted">
    If your intent is malicious, you can ignore this message.<br>
    If you believe this is a mistake, email the details below to the sites administrator.
  </p>

  <dl class="support" id="support-details">
    <dt>Reference</dt>
    <dd><?= h($ref) ?></dd>

    <dt>Site</dt>
    <dd><?= h($host) ?></dd>

    <dt>Your IP</dt>
    <dd><?= h($ip) ?></dd>

<?php if ($country !== ''): ?>
    <dt>Country</dt>
    <dd><?= h($country) ?></dd>
<?php endif; ?>

<?php if ($edge !== ''): ?>
    <dt>Edge node</dt>
    <dd><?= h($edge) ?>
      <span class="muted" style="display:block;font-weight:normal;font-size:0.85em;">
        Ideally from the block intercept; confirm with your WAF team if this matches the 403 response.
      </span>
    </dd>
<?php endif; ?>

<?php if ($blockId !== ''): ?>
    <dt>Block ID</dt>
    <dd><?= h($blockId) ?></dd>
<?php endif; ?>

    <dt>Block intercept</dt>
    <dd><?= $referer !== '' ? h($referer) : '<em>not provided</em>' ?></dd>

    <dt>Time</dt>
    <dd><?= h($when) ?></dd>

    <dt>Browser</dt>
    <dd><?= h($ua) ?></dd>
  </dl>

  <p class="muted">But mistakes do happen — include everything in the box above when you contact support.</p>

<?php if ($debug): ?>
  <pre class="debug"><?php
    foreach ($_SERVER as $k => $v) {
        if (strpos($k, 'HTTP_') === 0
            || stripos($k, 'SUCURI') !== false
            || in_array($k, ['REQUEST_URI', 'QUERY_STRING', 'REMOTE_ADDR'], true)) {
            echo h("$k = $v\n");
        }
    }
  ?></pre>
<?php endif; ?>
</body>
</html>
