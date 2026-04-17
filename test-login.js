

async function test() {
  const r = await fetch('http://localhost:5000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'admin@rentrow.com', password: 'admin_password_123' })
  });
  console.log(r.status);
  console.log(await r.json());
}
test();
