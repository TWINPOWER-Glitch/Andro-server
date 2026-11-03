
import { Router } from 'express';

const supabaseUrl = process.env.SUPABASE_URL ?? '';
const supabasePublicKey =
  process.env.SUPABASE_PUBLISHABLE_KEY ??
  process.env.SUPABASE_ANON_KEY ??
  '';

const page = String.raw`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Andro — Android development with AI</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, sans-serif; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      background: #10131b; color: #f4f6fb;
    }
    main {
      width: min(92vw, 560px); box-sizing: border-box; padding: 36px;
      border: 1px solid #2a3040; border-radius: 20px; background: #171c27;
    }
    h1 { margin: 0 0 12px; font-size: 2.4rem; }
    p { color: #b9c1d2; line-height: 1.6; }
    button {
      margin-top: 16px; border: 0; border-radius: 10px;
      padding: 13px 18px; font: inherit; font-weight: 650;
      cursor: pointer; background: #e7ecf7; color: #111521;
    }
    button.secondary { background: #2a3040; color: #f4f6fb; margin-left: 8px; }
    #message { overflow-wrap: anywhere; min-height: 1.5em; }
    .muted { font-size: .9rem; }
  </style>
</head>
<body>
  <main>
    <h1>Andro</h1>
    <p>One Andro account across the Android app and website. Sign in securely with GitHub.</p>
    <div id="actions"><button id="signin">Continue with GitHub</button></div>
    <p id="message" role="status"></p>
    <p class="muted">
      The Android app download will be listed here when the Play Store release is available.
    </p>
  </main>

  <script type="module">
    import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

    const url = ${JSON.stringify(supabaseUrl)};
    const key = ${JSON.stringify(supabasePublicKey)};
    const actions = document.querySelector('#actions');
    const message = document.querySelector('#message');

    if (!url || !key) {
      message.textContent =
        'Website sign-in is not configured. Set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY (or SUPABASE_ANON_KEY) in the deployment environment.';
      document.querySelector('#signin').disabled = true;
    } else {
      const supabase = createClient(url, key, {
        auth: {
          flowType: 'pkce',
          detectSessionInUrl: true,
          persistSession: true,
          autoRefreshToken: true
        }
      });

      async function render() {
        const { data: { session }, error } = await supabase.auth.getSession();

        if (error) message.textContent = error.message;
        if (!session) return;

        actions.replaceChildren();

        const signedIn = document.createElement('p');
        signedIn.textContent =
          'Signed in as ' +
          (session.user.user_metadata?.user_name ||
           session.user.email ||
           'your GitHub account') +
          '.';

        const signout = document.createElement('button');
        signout.className = 'secondary';
        signout.textContent = 'Sign out';

        signout.addEventListener('click', async () => {
          const { error: signOutError } = await supabase.auth.signOut();
          message.textContent = signOutError ? signOutError.message : 'Signed out.';
          await render();
        });

        actions.append(signedIn, signout);
        message.textContent =
          location.pathname === '/auth/callback'
            ? 'Authentication completed.'
            : '';
      }

      document.querySelector('#signin').addEventListener('click', async () => {
        message.textContent = 'Redirecting to GitHub…';

        const { error } = await supabase.auth.signInWithOAuth({
          provider: 'github',
          options: {
            redirectTo: location.origin + '/auth/callback'
          }
        });

        if (error) message.textContent = error.message;
      });

      supabase.auth.onAuthStateChange(() => {
        void render();
      });

      void render();
    }
  </script>
</body>
</html>`;

export function createSiteRouter() {
  const router = Router();

  router.get(['/', '/auth/callback'], (_req, res) => {
    res.type('html').send(page);
  });

  return router;
}
