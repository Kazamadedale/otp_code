<?php
  // Longueur du code OTP
define('TOTP_STEP',     30);   // Fenêtre de temps en secondes
define('TOTP_WINDOW',   1);    // Tolérance ±1 fenêtre (décalage horloge)
define('TOTP_ALGO',     'sha1'); // Algorithme HMAC (RFC 6238 = SHA1)

//  Base32 encode/decode 
class Base32 {
    private const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function encode(string $data): string {
        $out = '';
        $buf = 0; $bits = 0;
        foreach (str_split($data) as $c) {
            $buf = ($buf << 8) | ord($c);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out .= self::CHARS[($buf >> $bits) & 0x1F];
            }
        }
        if ($bits > 0) $out .= self::CHARS[($buf << (5 - $bits)) & 0x1F];
        while (strlen($out) % 8 !== 0) $out .= '=';
        return $out;
    }

    public static function decode(string $data): string {
        $data = strtoupper(rtrim($data, '='));
        $out  = '';
        $buf  = 0; $bits = 0;
        foreach (str_split($data) as $c) {
            $val = strpos(self::CHARS, $c);
            if ($val === false) continue;
            $buf = ($buf << 5) | $val;
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($buf >> $bits) & 0xFF);
            }
        }
        return $out;
    }
}

// ── Classe TOTP (RFC 6238) ────────────────────────────────
class TOTP {

    // Générer un secret aléatoire (20 octets = 160 bits)
    public static function generateSecret(int $bytes = 20): string {
        return Base32::encode(random_bytes($bytes));
    }

    // Calculer le code TOTP pour un timestamp donné
    public static function getCode(string $secret, int $timestamp = 0): string {
        if ($timestamp === 0) $timestamp = time();

        $counter = (int) floor($timestamp / TOTP_STEP);
        $key     = Base32::decode($secret);

        // RFC 6238 : HMAC-SHA1 du counter sur 8 octets big-endian
        $msg  = pack('J', $counter); // 64-bit big-endian unsigned
        $hash = hash_hmac(TOTP_ALGO, $msg, $key, true);

        // Dynamic truncation (RFC 4226 §5.3)
        $offset = ord($hash[19]) & 0x0F;
        $code   = (
            ((ord($hash[$offset])     & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) <<  8) |
             (ord($hash[$offset + 3]) & 0xFF)
        );

        return str_pad($code % (10 ** TOTP_DIGITS), TOTP_DIGITS, '0', STR_PAD_LEFT);
    }

    // Vérifier un code avec tolérance (±TOTP_WINDOW fenêtres)
    public static function verify(string $secret, string $code, int $timestamp = 0): bool {
        if ($timestamp === 0) $timestamp = time();
        $code = trim($code);
        if (strlen($code) !== TOTP_DIGITS || !ctype_digit($code)) return false;

        for ($i = -TOTP_WINDOW; $i <= TOTP_WINDOW; $i++) {
            $t = $timestamp + ($i * TOTP_STEP);
            if (hash_equals(self::getCode($secret, $t), $code)) return true;
        }
        return false;
    }

    // Générer l'URI otpauth:// pour le QR code
    public static function getUri(string $secret, string $account, string $issuer): string {
        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
            rawurlencode($issuer),
            rawurlencode($account),
            $secret,
            rawurlencode($issuer),
            TOTP_DIGITS,
            TOTP_STEP
        );
    }

    // Temps restant avant expiration du code
    public static function timeRemaining(): int {
        return TOTP_STEP - (time() % TOTP_STEP);
    }

    // Codes passé / actuel / suivant 
    public static function getCodes(string $secret): array {
        $t = time();
        return [
            'previous' => self::getCode($secret, $t - TOTP_STEP),
            'current'  => self::getCode($secret, $t),
            'next'     => self::getCode($secret, $t + TOTP_STEP),
        ];
    }
}

// Session simple 
session_start();

$action  = $_POST['action'] ?? $_GET['action'] ?? '';
$msg     = '';
$msgType = '';
$secret  = $_SESSION['totp_secret'] ?? null;
$account = $_SESSION['totp_account'] ?? 'user@example.com';
$issuer  = $_SESSION['totp_issuer']  ?? 'MonApp';

// ── Actions ──────────────────────────────────────────────
if ($action === 'generate') {
    $secret  = TOTP::generateSecret();
    $account = htmlspecialchars(trim($_POST['account'] ?? 'user@example.com'));
    $issuer  = htmlspecialchars(trim($_POST['issuer']  ?? 'MonApp'));
    $_SESSION['totp_secret']  = $secret;
    $_SESSION['totp_account'] = $account;
    $_SESSION['totp_issuer']  = $issuer;
    $msg     = '✅ Secret généré ! Scannez le QR code avec votre application TOTP.';
    $msgType = 'success';
}

if ($action === 'verify' && $secret) {
    $code   = trim($_POST['code'] ?? '');
    $valid  = TOTP::verify($secret, $code);
    $msg     = $valid
        ? '✅ Code valide — authentification réussie !'
        : '❌ Code invalide ou expiré. Réessayez.';
    $msgType = $valid ? 'success' : 'danger';
}

if ($action === 'reset') {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// ── Données pour l'affichage ──────────────────────────────
$uri        = $secret ? TOTP::getUri($secret, $account, $issuer) : null;
$codes      = $secret ? TOTP::getCodes($secret) : null;
$remaining  = TOTP::timeRemaining();
$qrUrl      = $uri ? 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . rawurlencode($uri) : null;
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>2FA TOTP — Outil Éducatif</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Manrope:wght@400;600;800&display=swap" rel="stylesheet">
<style>
:root {
    --bg:      #f0f4f8;
    --surface: #ffffff;
    --card:    #ffffff;
    --border:  #e2e8f0;
    --accent:  #2563eb;
    --accent2: #7c3aed;
    --success: #16a34a;
    --danger:  #dc2626;
    --text:    #1e293b;
    --muted:   #94a3b8;
    --light:   #f8fafc;
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Manrope', sans-serif;
    min-height: 100vh;
}

header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 1.2rem 3rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
}
.logo { font-size: 1.3rem; font-weight: 800; letter-spacing: -0.03em; }
.logo span { color: var(--accent); }
.badge {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.62rem;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    background: #fef2f2;
    color: var(--danger);
    border: 1px solid #fecaca;
}

main {
    max-width: 960px;
    margin: 2.5rem auto;
    padding: 0 1.5rem 5rem;
}

/* ── Disclaimer ── */
.disclaimer {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.65rem;
    color: var(--muted);
    padding: 0.7rem 1rem;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--light);
    margin-bottom: 2rem;
    line-height: 1.6;
}

/* ── Layout ── */
.layout { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
@media(max-width:700px) { .layout { grid-template-columns: 1fr; } }

/* ── Card ── */
.card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.8rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}
.card-title {
    font-size: 0.7rem;
    font-family: 'IBM Plex Mono', monospace;
    color: var(--muted);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 1.2rem;
}
h2 { font-size: 1.1rem; font-weight: 800; margin-bottom: 0.3rem; }
.sub { color: var(--muted); font-size: 0.85rem; margin-bottom: 1.5rem; }

/* ── Form ── */
label {
    display: block;
    font-size: 0.72rem;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 0.35rem;
    letter-spacing: 0.02em;
}
input[type=text], input[type=email] {
    width: 100%;
    border: 1.5px solid var(--border);
    border-radius: 8px;
    padding: 0.65rem 0.9rem;
    font-family: 'Manrope', sans-serif;
    font-size: 0.9rem;
    color: var(--text);
    background: var(--light);
    outline: none;
    transition: border-color 0.2s;
}
input:focus { border-color: var(--accent); background: #fff; }
.field { margin-bottom: 1rem; }

.btn {
    width: 100%;
    padding: 0.75rem;
    border-radius: 10px;
    border: none;
    font-family: 'Manrope', sans-serif;
    font-size: 0.9rem;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s;
    margin-top: 0.5rem;
}
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: #1d4ed8; transform: translateY(-1px); }
.btn-danger { background: #fef2f2; color: var(--danger); border: 1px solid #fecaca; }
.btn-danger:hover { background: #fee2e2; }

/* ── Alert ── */
.alert {
    padding: 0.8rem 1rem;
    border-radius: 8px;
    font-size: 0.85rem;
    font-weight: 600;
    margin-bottom: 1rem;
}
.alert-success { background: #f0fdf4; color: var(--success); border: 1px solid #bbf7d0; }
.alert-danger  { background: #fef2f2; color: var(--danger);  border: 1px solid #fecaca; }

/* ── QR + Secret ── */
.qr-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
    padding: 1.2rem;
    background: var(--light);
    border-radius: 12px;
    border: 1px solid var(--border);
    margin-bottom: 1rem;
}
.qr-wrap img { border-radius: 8px; border: 4px solid #fff; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }

.secret-box {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.9rem;
    letter-spacing: 0.15em;
    background: #fff;
    border: 1.5px dashed var(--border);
    border-radius: 8px;
    padding: 0.7rem 1rem;
    text-align: center;
    word-break: break-all;
    color: var(--accent2);
    cursor: pointer;
    transition: border-color 0.2s;
}
.secret-box:hover { border-color: var(--accent2); }

/* ── Code display ── */
.codes-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.6rem;
    margin-bottom: 1rem;
}
.code-item {
    text-align: center;
    padding: 0.8rem 0.5rem;
    border-radius: 10px;
    border: 1.5px solid var(--border);
}
.code-item.current {
    border-color: var(--accent);
    background: #eff6ff;
}
.code-val {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 1.4rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    color: var(--text);
}
.code-item.current .code-val { color: var(--accent); }
.code-lbl {
    font-size: 0.65rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 0.2rem;
}

/* ── Timer ── */
.timer-wrap {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    margin-bottom: 1rem;
}
.timer-bar-bg {
    flex: 1;
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    overflow: hidden;
}
.timer-bar {
    height: 100%;
    border-radius: 3px;
    background: var(--accent);
    transition: width 1s linear;
}
.timer-val {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.8rem;
    color: var(--muted);
    min-width: 3rem;
    text-align: right;
}

/* ── OTP input ── */
.otp-input {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 2rem;
    font-weight: 600;
    letter-spacing: 0.4em;
    text-align: center;
    width: 100%;
    border: 2px solid var(--border);
    border-radius: 10px;
    padding: 0.8rem;
    color: var(--text);
    background: var(--light);
    outline: none;
    transition: border-color 0.2s;
}
.otp-input:focus { border-color: var(--accent); background: #fff; }

/* ── Explainer ── */
.steps { list-style: none; counter-reset: steps; }
.steps li {
    counter-increment: steps;
    display: flex;
    gap: 0.8rem;
    align-items: flex-start;
    margin-bottom: 0.9rem;
    font-size: 0.85rem;
    line-height: 1.5;
}
.steps li::before {
    content: counter(steps);
    min-width: 24px; height: 24px;
    border-radius: 50%;
    background: var(--accent);
    color: #fff;
    font-size: 0.7rem;
    font-weight: 800;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    margin-top: 0.1rem;
}

/* ── Info box ── */
.info-box {
    background: #f0f4ff;
    border: 1px solid #c7d2fe;
    border-radius: 8px;
    padding: 0.8rem 1rem;
    font-size: 0.8rem;
    color: #3730a3;
    line-height: 1.6;
    margin-bottom: 1rem;
}
</style>
</head>
<body>

<header>
    <div class="logo">2FA <span>TOTP</span></div>
    <span class="badge">ÉDUCATIF UNIQUEMENT</span>
</header>

<main>
    <div class="disclaimer">
        ⚠️ Implémentation éducative de RFC 6238. Ne jamais utiliser en production sans audit de sécurité.
        Cet outil est destiné à comprendre le fonctionnement interne du TOTP.
    </div>

    <?php if ($msg): ?>
    <div class="alert alert-<?= $msgType ?>"><?= $msg ?></div>
    <?php endif; ?>

    <div class="layout">

        <!-- ── Colonne gauche ── -->
        <div>
            <?php if (!$secret): ?>
            <!-- Formulaire de génération -->
            <div class="card">
                <div class="card-title">// Étape 1 — Configurer</div>
                <h2>Générer un secret TOTP</h2>
                <p class="sub">Créez un secret partagé pour lier votre compte à une app 2FA.</p>
                <form method="POST">
                    <input type="hidden" name="action" value="generate">
                    <div class="field">
                        <label>Compte (email / username)</label>
                        <input type="email" name="account" value="user@example.com" required>
                    </div>
                    <div class="field">
                        <label>Nom de l'application</label>
                        <input type="text" name="issuer" value="MonApp" required>
                    </div>
                    <button type="submit" class="btn btn-primary">⚡ Générer le secret</button>
                </form>
            </div>

            <!-- Explainer -->
            <div class="card" style="margin-top:1.5rem">
                <div class="card-title">// Comment ça marche</div>
                <ol class="steps">
                    <li>Un <strong>secret partagé</strong> (Base32) est généré côté serveur.</li>
                    <li>L'utilisateur le scanne via <strong>QR code</strong> dans son app TOTP.</li>
                    <li>Chaque 30s, l'app calcule <strong>HMAC-SHA1(secret, floor(time/30))</strong>.</li>
                    <li>Le serveur recalcule le même code et <strong>compare</strong> (hash_equals).</li>
                    <li>Tolérance ±1 fenêtre pour compenser le <strong>décalage d'horloge</strong>.</li>
                </ol>
            </div>

            <?php else: ?>
            <!-- QR Code + Secret -->
            <div class="card">
                <div class="card-title">// Étape 2 — Scanner</div>
                <h2>Scannez le QR code</h2>
                <p class="sub">Ouvrez Google Authenticator, Authy ou Aegis et scannez ce code.</p>

                <div class="qr-wrap">
                    <img src="<?= htmlspecialchars($qrUrl) ?>" alt="QR Code TOTP" width="200" height="200">
                    <div style="font-size:0.75rem; color:var(--muted); text-align:center;">
                        <?= htmlspecialchars($issuer) ?> — <?= htmlspecialchars($account) ?>
                    </div>
                </div>

                <label style="margin-bottom:0.4rem;">Secret (saisie manuelle)</label>
                <div class="secret-box" onclick="copySecret(this)" title="Cliquer pour copier">
                    <?= htmlspecialchars(chunk_split($secret, 4, ' ')) ?>
                </div>
                <div style="font-size:0.72rem;color:var(--muted);margin-top:0.3rem;margin-bottom:1rem;">
                    Cliquez pour copier · 20 octets · Base32 · SHA1 · 6 chiffres · 30s
                </div>

                <form method="POST" style="margin-top:0.5rem">
                    <input type="hidden" name="action" value="reset">
                    <button type="submit" class="btn btn-danger">🔄 Réinitialiser</button>
                </form>
            </div>

            <!-- Codes live -->
            <div class="card" style="margin-top:1.5rem">
                <div class="card-title">// Codes générés (démo)</div>
                <div class="info-box">
                    Ces codes sont calculés côté serveur from scratch via RFC 6238.
                    Ils doivent correspondre exactement à votre app TOTP.
                </div>
                <div class="codes-grid">
                    <div class="code-item">
                        <div class="code-val"><?= $codes['previous'] ?></div>
                        <div class="code-lbl">Précédent</div>
                    </div>
                    <div class="code-item current">
                        <div class="code-val" id="live-code"><?= $codes['current'] ?></div>
                        <div class="code-lbl">✓ Actuel</div>
                    </div>
                    <div class="code-item">
                        <div class="code-val"><?= $codes['next'] ?></div>
                        <div class="code-lbl">Suivant</div>
                    </div>
                </div>
                <div class="timer-wrap">
                    <div class="timer-bar-bg">
                        <div class="timer-bar" id="timer-bar" style="width:<?= ($remaining / TOTP_STEP * 100) ?>%"></div>
                    </div>
                    <div class="timer-val" id="timer-val"><?= $remaining ?>s</div>
                </div>
                <div style="font-size:0.72rem;color:var(--muted);">
                    Le code change toutes les 30 secondes. La page se recharge automatiquement.
                </div>
            </div>
            <?php endif; ?>
        </div>

        <!-- ── Colonne droite ── -->
        <div>
            <?php if ($secret): ?>
            <!-- Vérification -->
            <div class="card">
                <div class="card-title">// Étape 3 — Vérifier</div>
                <h2>Entrez votre code</h2>
                <p class="sub">Ouvrez votre app TOTP et entrez le code à 6 chiffres.</p>
                <form method="POST">
                    <input type="hidden" name="action" value="verify">
                    <div class="field">
                        <label>Code OTP (6 chiffres)</label>
                        <input
                            type="text"
                            name="code"
                            class="otp-input"
                            maxlength="6"
                            pattern="\d{6}"
                            placeholder="000000"
                            autocomplete="one-time-code"
                            autofocus
                            required
                        >
                    </div>
                    <button type="submit" class="btn btn-primary">🔐 Vérifier le code</button>
                </form>
            </div>
            <?php endif; ?>

            <!-- Explainer technique -->
            <div class="card" style="margin-top:<?= $secret ? '1.5rem' : '0' ?>">
                <div class="card-title">// Internals — RFC 6238</div>
                <div style="font-family:'IBM Plex Mono',monospace; font-size:0.75rem; line-height:2; color:var(--text);">
                    <div style="color:var(--muted); margin-bottom:0.5rem;">// Algorithme TOTP simplifié</div>
                    <div><span style="color:var(--accent2)">counter</span> = floor(time() / <span style="color:#16a34a">30</span>)</div>
                    <div><span style="color:var(--accent2)">key</span>     = base32_decode(secret)</div>
                    <div><span style="color:var(--accent2)">msg</span>     = pack('J', counter) <span style="color:var(--muted)">// 8 octets big-endian</span></div>
                    <div><span style="color:var(--accent2)">hash</span>    = hmac_sha1(key, msg)</div>
                    <div><span style="color:var(--accent2)">offset</span>  = hash[19] & 0x0F</div>
                    <div><span style="color:var(--accent2)">code</span>    = (hash[offset..+4] & 0x7FFFFFFF) % 10^6</div>
                </div>

                <div style="height:1px;background:var(--border);margin:1.2rem 0;"></div>

                <div style="font-size:0.8rem; line-height:1.7; color:var(--muted);">
                    <strong style="color:var(--text)">Pourquoi c'est sécurisé ?</strong><br>
                    • Secret jamais transmis après setup<br>
                    • Code valide seulement 30 secondes<br>
                    • HMAC rend la prédiction impossible sans le secret<br>
                    • <code style="font-size:0.72rem;">hash_equals()</code> prévient les timing attacks<br>
                    • Tolérance ±1 fenêtre pour les horloges décalées
                </div>

                <div style="height:1px;background:var(--border);margin:1.2rem 0;"></div>

                <div style="font-size:0.8rem; color:var(--muted);">
                    <strong style="color:var(--text)">Apps compatibles</strong><br>
                    Google Authenticator · Authy · Aegis · Bitwarden · 1Password · FreeOTP
                </div>
            </div>
        </div>
    </div>
</main>

<script>
// ── Timer côté client ─────────────────────────────────────
let remaining = <?= $remaining ?>;
const bar = document.getElementById('timer-bar');
const val = document.getElementById('timer-val');

function tick() {
    remaining--;
    if (remaining <= 0) {
        location.reload(); // Reload pour rafraîchir les codes PHP
        return;
    }
    const pct = (remaining / 30) * 100;
    if (bar) bar.style.width = pct + '%';
    if (val) val.textContent = remaining + 's';

    // Couleur d'urgence
    if (bar) bar.style.background = remaining <= 10 ? '#dc2626' : '#2563eb';
}

setInterval(tick, 1000);

// ── Copie du secret ───────────────────────────────────────
function copySecret(el) {
    const text = el.textContent.replace(/\s/g, '');
    navigator.clipboard.writeText(text).then(() => {
        const orig = el.textContent;
        el.textContent = '✅ Copié !';
        setTimeout(() => el.textContent = orig, 1500);
    });
}

// ── Auto-focus + format OTP input ─────────────────────────
const otpInput = document.querySelector('.otp-input');
if (otpInput) {
    otpInput.addEventListener('input', function() {
        this.value = this.value.replace(/\D/g, '').slice(0, 6);
    });
}
</script>

</body>
</html>
