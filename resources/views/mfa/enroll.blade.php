<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Set up your authenticator app</title>
</head>
<body>
<main style="max-width: 28rem; margin: 3rem auto; font-family: sans-serif;">
    <h1>Set up your authenticator app</h1>
    <ol>
        <li>Install an authenticator app (Google Authenticator, Microsoft Authenticator, Authy...).</li>
        <li>Scan the QR code, or type the key into the app.</li>
        <li>Enter the 6-digit code the app shows.</li>
    </ol>

    @if ($qr)
        <div>{!! $qr !!}</div>
    @endif

    <p>Key: <code>{{ $secret }}</code></p>

    <form method="POST" action="{{ route('mfa.enroll.confirm') }}">
        @csrf
        <label for="code">6-digit code</label>
        <input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" required autofocus>
        @error('code') <p role="alert">{{ $message }}</p> @enderror
        <button type="submit">Confirm</button>
    </form>
</main>
</body>
</html>
