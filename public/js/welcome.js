document.addEventListener('DOMContentLoaded', async () => {
  const loadingBox = document.getElementById('loadingBox');
  const contentBox = document.getElementById('contentBox');
  const userEmail = document.getElementById('userEmail');
  const logoutBtn = document.getElementById('logoutBtn');
  const errorBox = document.getElementById('errorBox');

  try {
    // Relative URL fetch() to get current authenticated user data
    const response = await fetch('/api/me', {
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    });

    if (response.status === 401 || !response.ok) {
      // Unauthenticated: redirect to login page immediately
      window.location.href = '/login.html';
      return;
    }

    const data = await response.json();

    loadingBox.style.display = 'none';
    contentBox.style.display = 'block';
    userEmail.textContent = `Welcome, ${data.email}`;

  } catch (err) {
    loadingBox.style.display = 'none';
    errorBox.style.display = 'block';
    errorBox.textContent = 'Failed to retrieve session data. Redirecting to login...';
    setTimeout(() => {
      window.location.href = '/login.html';
    }, 2000);
  }

  // Logout handler
  logoutBtn.addEventListener('click', async () => {
    logoutBtn.disabled = true;
    logoutBtn.textContent = 'Signing Out...';

    try {
      await fetch('/api/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });
    } catch (e) {
      console.error('Logout error:', e);
    } finally {
      window.location.href = '/login.html';
    }
  });
});
