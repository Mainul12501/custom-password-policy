<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Your recovery codes</title>
</head>
<body>
<main style="max-width: 28rem; margin: 3rem auto; font-family: sans-serif;">
    <h1>Your recovery codes</h1>
    <p>Save these now. Each code works once if you lose your phone. They will not be shown again.</p>

    <ul>
        @foreach ($codes as $code)
            <li><code>{{ $code }}</code></li>
        @endforeach
    </ul>

    <a href="{{ url('/') }}">Continue</a>
</main>
</body>
</html>
