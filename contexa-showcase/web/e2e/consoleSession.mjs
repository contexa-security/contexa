// docs/agent RW-2, RW-3: an operator's browser session on control D's admin console through the portal's ops port
// (ConsoleSessionOpsController): a security administrator of control D, signed in through control D's own sign-in
// (password, then the one-time code the demo inbox received), removed when closed.

export async function openSession(ops) {
  const answer = await fetch(`${ops}/ops/console-sessions`, { method: 'POST' });
  if (answer.status !== 200) {
    throw new Error(`no console session: HTTP ${answer.status}`);
  }
  const session = await answer.json();
  session.console = session.console.replace(/[/]+$/, '');
  return session;
}

async function oneTimeCode(ops, key) {
  for (let i = 0; i < 30; i += 1) {
    const answer = await fetch(`${ops}/ops/console-sessions/${key}/code`);
    if (answer.status === 200) {
      return (await answer.json()).code;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  return null;
}

export async function signIn(page, ops, session) {
  await page.goto(`${session.console}/mfa/login`);
  await page.fill('#username', session.username);
  await page.fill('#password', session.password);
  await page.click('#loginButton');
  await page.waitForURL(/request-code-ui/, { timeout: 20000 });
  const email = page.locator('#email');
  if ((await email.inputValue()) === '') {
    await email.fill(session.email);
  }
  await page.click('button[type=submit]');
  await page.waitForURL(/challenge\/ott/, { timeout: 20000 });
  const code = await oneTimeCode(ops, session.key);
  if (!code) {
    throw new Error('no one-time code in the demo inbox');
  }
  await page.fill('#token', code);
  await page.locator('button[type=submit]').first().click();
  await page.waitForURL((url) => !url.pathname.startsWith('/mfa/challenge'), { timeout: 20000 });
}

export async function closeSession(ops, session) {
  return (await fetch(`${ops}/ops/console-sessions/${session.key}`, { method: 'DELETE' })).status;
}
