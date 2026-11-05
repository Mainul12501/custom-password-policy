<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Enter your code</title>
</head>
<body>
<main style="max-width: 28rem; margin: 3rem auto; font-family: sans-serif;">
    <h1>Enter your code</h1>
    <p>Open your authenticator app and type the 6-digit code. Lost your phone? Use a recovery code instead.</p>

    <form method="POST" action="{{ route('mfa.verify') }}">
        @csrf
        <label for="code">Code</label>
        <input id="code" name="code" type="text" autocomplete="one-time-code" required autofocus>
        @error('code') <p role="alert">{{ $message }}</p> @enderror
        <button type="submit">Verify</button>
    </form>
</main>
</body>
</html>
