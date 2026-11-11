import { useState, useEffect, useRef } from 'react';
import './App.css';

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:5000/api';
const apiFetch = (path, options = {}) => fetch(API_BASE + path, {
  ...options,
  credentials: 'include',
  headers: {
    ...options.headers,
    ...(options.method === 'POST' ? { 'X-Requested-With': 'SecureAccountApp' } : {})
  }
});

const readResponse = (response) => {
  if (response.headers.get('content-type')?.includes('json')) return response.json();
  if (response.status === 401) return { message: 'Увійдіть у свій акаунт.' };
  if (response.status === 403) return { message: 'Недостатньо прав для цієї дії.' };
  if (response.status === 429) return { message: 'Забагато запитів. Спробуйте за хвилину.' };
  return {};
};

export default function App() {
  const [linkParams] = useState(() => new URLSearchParams(window.location.search));
  const [authMode, setAuthMode] = useState(linkParams.has('resetToken') ? 'reset' : 'login');
  const activationRequested = useRef(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [resetToken, setResetToken] = useState(linkParams.get('resetToken') ?? '');
  const [captcha, setCaptcha] = useState(null);
  const [captchaCode, setCaptchaCode] = useState('');
  const [captchaError, setCaptchaError] = useState('');
  const [captchaLoading, setCaptchaLoading] = useState(false);
  const [googleClientId, setGoogleClientId] = useState(null);
  const [twoFactorChallenge, setTwoFactorChallenge] = useState('');

  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [twoFactorEmail, setTwoFactorEmail] = useState('');

  const [user, setUser] = useState(null);
  const [message, setMessage] = useState(
    resetToken ? 'Введіть новий пароль для вашого облікового запису.' : ''
  );
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const [activeTab, setActiveTab] = useState('profile'); // 'profile' | 'users' | 'logs'
  const [adminUsers, setAdminUsers] = useState([]);
  const [adminLogs, setAdminLogs] = useState([]);
  const [adminLoading, setAdminLoading] = useState(false);

  const loadCaptcha = async () => {
    setCaptchaLoading(true);
    setCaptchaCode('');
    setCaptcha(null);
    setCaptchaError('');
    try {
      const res = await apiFetch('/auth/captcha');
      const data = await readResponse(res);
      if (res.ok) setCaptcha(data);
      else setCaptchaError(data.message || 'Не вдалося завантажити CAPTCHA.');
    } catch {
      setCaptchaError('Не вдалося завантажити CAPTCHA.');
    } finally {
      setCaptchaLoading(false);
    }
  };

  const readProfile = async () => {
    const res = await apiFetch('/auth/me');
    return res.ok ? (await readResponse(res)).user : null;
  };

  const handleGoogleCallback = async (response) => {
    if (!response || !response.credential) return;

    setLoading(true);
    setError('');
    setMessage('');

    try {
      const res = await apiFetch(`/auth/google-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken: response.credential }),
      });

      const data = await readResponse(res);

      if (!res.ok) {
        setError(data.message || 'Помилка входу через Google.');
      } else {
        if (data.requiresTwoFactor) {
          setTwoFactorEmail(data.email);
          setTwoFactorChallenge(data.challenge);
          setTwoFactorCode('');
          setAuthMode('twoFactor');
          setMessage(data.message);
        } else if (data.user) {
          setUser(data.user);
          setMessage(data.message || 'Успішний вхід через Google!');
          setPassword('');
        }
      }
    } catch {
      setError('Не вдалося з’єднатися із сервером під час входу через Google.');
    } finally {
      setLoading(false);
    }
  };

  const activateAccount = async (token) => {
    try {
      const res = await apiFetch(`/auth/activate?token=${encodeURIComponent(token)}`);
      const data = await readResponse(res);
      if (!res.ok) {
        setError(data.message || 'Помилка активації.');
      } else {
        setMessage(data.message || 'Обліковий запис успішно активовано!');
        setUser(await readProfile());
        window.history.replaceState({}, document.title, window.location.pathname);
      }
    } catch {
      setError('Не вдалося з’єднатися із сервером під час активації.');
    }
  };

  useEffect(() => {
    apiFetch('/auth/google-config')
      .then(readResponse)
      .then(({ clientId }) => setGoogleClientId(clientId))
      .catch(() => setGoogleClientId(null));

    if (linkParams.has('resetToken')) {
      window.history.replaceState({}, document.title, window.location.pathname);
      return;
    }

    const token = linkParams.get('token');
    if (token) {
      window.history.replaceState({}, document.title, window.location.pathname);
      if (!activationRequested.current) {
        activationRequested.current = true;
        activateAccount(token);
      }
    } else {
      readProfile().then(setUser).catch(() => {});
    }
  }, [linkParams]);

  useEffect(() => {
    if (!googleClientId || user || !['login', 'register'].includes(authMode)) return;

    const renderGoogleButton = () => {
      if (window.google && window.google.accounts) {
        try {
          window.google.accounts.id.initialize({
            client_id: googleClientId,
            callback: handleGoogleCallback,
          });

          const btnContainer = document.getElementById('googleSignInBtn');
          if (btnContainer) {
            btnContainer.innerHTML = '';
            window.google.accounts.id.renderButton(btnContainer, {
              theme: 'outline',
              size: 'large',
              width: 350,
              text: 'continue_with',
              locale: 'uk',
              shape: 'rectangular'
            });
          }
        } catch {
        }
      }
    };

    renderGoogleButton();

    const timer = setInterval(() => {
      if (window.google && window.google.accounts) {
        renderGoogleButton();
        clearInterval(timer);
      }
    }, 400);

    return () => clearInterval(timer);
  }, [authMode, googleClientId, user]);

  const getPasswordStrength = (pass) => {
    if (!pass) return { score: 0, label: '', color: 'transparent' };
    let score = 0;
    if (pass.length >= 8) score++;
    if (/[A-Z]/.test(pass)) score++;
    if (/[a-z]/.test(pass)) score++;
    if (/[0-9]/.test(pass)) score++;
    if (/[^\p{L}\p{N}\s]/u.test(pass)) score++;

    switch (score) {
      case 1: return { score, label: 'Дуже слабкий', color: '#f87171' };
      case 2: return { score, label: 'Слабкий', color: '#fb923c' };
      case 3: return { score, label: 'Середній', color: '#facc15' };
      case 4: return { score, label: 'Хороший', color: '#a3e635' };
      case 5: return { score, label: 'Надійний', color: '#34d399' };
      default: return { score: 0, label: '', color: 'transparent' };
    }
  };

  const strengthInfo = getPasswordStrength(password);

  const fetchAdminUsers = async () => {
    if (!user || user.role !== 'Admin') return;
    try {
      setAdminLoading(true);
      const res = await apiFetch('/admin/users');
      const data = await readResponse(res);
      if (res.ok) {
        setAdminUsers(data);
      } else {
        setError(data.message || 'Помилка завантаження користувачів.');
      }
    } catch {
      setError('Не вдалося завантажити список користувачів.');
    } finally {
      setAdminLoading(false);
    }
  };

  const fetchAdminLogs = async () => {
    if (!user || user.role !== 'Admin') return;
    try {
      setAdminLoading(true);
      const res = await apiFetch('/admin/logs');
      const data = await readResponse(res);
      if (res.ok) {
        setAdminLogs(data);
      } else {
        setError(data.message || 'Помилка завантаження журналу логів.');
      }
    } catch {
      setError('Не вдалося завантажити журнал логів.');
    } finally {
      setAdminLoading(false);
    }
  };

  const toggleBlockUser = async (targetUserId) => {
    try {
      setMessage('');
      setError('');
      const res = await apiFetch(`/admin/toggle-block/${targetUserId}`, {
        method: 'POST',
      });
      const data = await readResponse(res);
      if (!res.ok) {
        setError(data.message || 'Не вдалося змінити статус блокування.');
      } else {
        setMessage(data.message);
        fetchAdminUsers();
      }
    } catch {
      setError('Помилка сервера при спробі блокування/розблокування.');
    }
  };

  const toggleRoleUser = async (targetUserId) => {
    try {
      setMessage('');
      setError('');
      const res = await apiFetch(`/admin/toggle-role/${targetUserId}`, {
        method: 'POST',
      });
      const data = await readResponse(res);
      if (!res.ok) {
        setError(data.message || 'Не вдалося змінити роль.');
      } else {
        setMessage(data.message);
        fetchAdminUsers();
      }
    } catch {
      setError('Помилка сервера при зміні ролі.');
    }
  };

  const handleToggleTwoFactor = async () => {
    if (!user) return;
    const newStatus = !user.twoFactorEnabled;
    try {
      setMessage('');
      setError('');
      const res = await apiFetch(`/auth/toggle-2fa`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enable: newStatus }),
      });
      const data = await readResponse(res);
      if (!res.ok) {
        setError(data.message || 'Помилка оновлення 2FA.');
      } else {
        setMessage(data.message);
        setUser({ ...user, twoFactorEnabled: newStatus });
      }
    } catch {
      setError('Не вдалося змінити налаштування 2FA.');
    }
  };

  const handleResendActivation = async () => {
    if (!user) return;
    try {
      setMessage('');
      setError('');
      const res = await apiFetch(`/auth/resend-activation`, {
        method: 'POST',
      });
      const data = await readResponse(res);
      if (res.ok) setMessage(data.message);
      else setError(data.message);
    } catch {
      setError('Помилка надсилання листа активації.');
    }
  };

  const handleAuthSubmit = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');
    setLoading(true);

    if (authMode === 'register') {
      try {
        const res = await apiFetch(`/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password, captchaId: captcha?.captchaId, captchaCode }),
        });

        const data = await readResponse(res);

        if (!res.ok) {
          setError(data.message || 'Помилка реєстрації.');
          await loadCaptcha();
        } else {
          setMessage(data.message || 'Реєстрація успішна!');
          setAuthMode('login');
          setPassword('');
        }
      } catch {
        setError('Не вдалося з’єднатися із сервером backend.');
      } finally {
        setLoading(false);
      }
    } else {
      try {
        const res = await apiFetch(`/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });

        const data = await readResponse(res);

        if (!res.ok) {
          setError(data.message || 'Невірний email або пароль.');
        } else {
          if (data.requiresTwoFactor) {
            setTwoFactorEmail(data.email || email);
            setTwoFactorChallenge(data.challenge);
            setTwoFactorCode('');
            setAuthMode('twoFactor');
            setMessage(data.message || 'Введіть 6-значний код, надісланий на вашу пошту.');
          } else if (data.user) {
            setUser(data.user);
            setMessage(data.message || 'Успішний вхід!');
            setPassword('');
          }
        }
      } catch {
        setError('Не вдалося з’єднатися із сервером backend.');
      } finally {
        setLoading(false);
      }
    }
  };

  const handleVerifyTwoFactor = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');
    setLoading(true);

    try {
      const res = await apiFetch(`/auth/verify-2fa`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challenge: twoFactorChallenge,
          code: twoFactorCode
        }),
      });

      const data = await readResponse(res);

      if (!res.ok) {
        setError(data.message || 'Невірний код підтвердження.');
      } else {
        setUser(data.user);
        setMessage(data.message || 'Вхід успішний!');
        setAuthMode('login');
        setPassword('');
        setTwoFactorCode('');
        setTwoFactorChallenge('');
      }
    } catch {
      setError('Не вдалося перевірити код 2FA.');
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPasswordSubmit = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');
    setLoading(true);

    try {
      const res = await apiFetch(`/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      const data = await readResponse(res);

      if (!res.ok) {
        setError(data.message || 'Помилка надсилання запиту.');
      } else {
        setMessage(data.message || 'Лист із посиланням надіслано на вашу пошту.');
      }
    } catch {
      setError('Не вдалося з’єднатися із сервером.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPasswordSubmit = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');

    if (password !== confirmPassword) {
      setError('Введені паролі не співпадають!');
      return;
    }

    setLoading(true);

    try {
      const res = await apiFetch(`/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: resetToken, newPassword: password }),
      });

      const data = await readResponse(res);

      if (!res.ok) {
        setError(data.message || 'Не вдалося скинути пароль.');
      } else {
        setMessage(data.message || 'Пароль успішно змінено!');
        window.history.replaceState({}, document.title, window.location.pathname);
        setResetToken('');
        setPassword('');
        setConfirmPassword('');
        setAuthMode('login');
      }
    } catch {
      setError('Не вдалося з’єднатися із сервером.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      const res = await apiFetch('/auth/logout', { method: 'POST' });
      if (!res.ok && res.status !== 401) {
        const data = await readResponse(res);
        setError(data.message || 'Не вдалося вийти із системи.');
        return;
      }
      setUser(null);
      setAuthMode('login');
      setActiveTab('profile');
      setAdminUsers([]);
      setAdminLogs([]);
      setEmail('');
      setPassword('');
      setMessage('Ви успішно вийшли з системи.');
      setError('');
    } catch {
      setError('Не вдалося вийти із системи.');
    }
  };

  const renderEyeIcon = () => (
    <button
      type="button"
      onClick={() => setShowPassword(!showPassword)}
      style={{
        position: 'absolute',
        right: '12px',
        background: 'none',
        border: 'none',
        cursor: 'pointer',
        padding: '4px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: '#d6c2be'
      }}
      title={showPassword ? 'Приховати пароль' : 'Показати пароль'}
    >
      {showPassword ? (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
          <line x1="1" y1="1" x2="23" y2="23"></line>
        </svg>
      ) : (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8z"></path>
          <circle cx="12" cy="12" r="3"></circle>
        </svg>
      )}
    </button>
  );

  // ВАРІАНТ 1: КОРИСТУВАЧ УВІЙШОВ У СИСТЕМУ
  if (user) {
    const isAdmin = user.role === 'Admin';

    return (
      <div className="auth-container">
        <div className={`auth-card ${isAdmin && activeTab !== 'profile' ? 'wide-card' : ''}`}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
            <h2 className="auth-title" style={{ margin: 0 }}>
              {isAdmin ? 'Кабінет адміністратора' : 'Особистий кабінет'}
            </h2>
            <button onClick={handleLogout} className="sm-btn sm-btn-danger" style={{ padding: '6px 14px' }}>
              Вийти
            </button>
          </div>

          {message && <div className="success-box">{message}</div>}
          {error && <div className="error-box">{error}</div>}

          {isAdmin && (
            <div className="nav-tabs">
              <button
                type="button"
                className={`tab-button ${activeTab === 'profile' ? 'active' : ''}`}
                onClick={() => { setActiveTab('profile'); setMessage(''); setError(''); }}
              >
                Мій профіль
              </button>
              <button
                type="button"
                className={`tab-button ${activeTab === 'users' ? 'active' : ''}`}
                onClick={() => { setActiveTab('users'); setMessage(''); setError(''); fetchAdminUsers(); }}
              >
                Користувачі
              </button>
              <button
                type="button"
                className={`tab-button ${activeTab === 'logs' ? 'active' : ''}`}
                onClick={() => { setActiveTab('logs'); setMessage(''); setError(''); fetchAdminLogs(); }}
              >
                Журнал спроб входу
              </button>
            </div>
          )}

          {(!isAdmin || activeTab === 'profile') && (
            <div>
              <div className="profile-info">
                <p><strong>Email:</strong> {user.email}</p>
                <p style={{ marginTop: '0.6rem' }}>
                  <strong>Роль (RBAC):</strong>{' '}
                  <span className={`role-badge ${user.role === 'Admin' ? 'badge-admin' : ''}`}>
                    {user.role}
                  </span>
                </p>
                <p style={{ marginTop: '0.6rem' }}>
                  <strong>Активація email:</strong>{' '}
                  <span className={`role-badge ${user.isActive ? 'badge-active' : 'badge-danger'}`}>
                    {user.isActive ? 'Активовано' : 'Не активовано'}
                  </span>
                </p>
                <p style={{ marginTop: '0.6rem' }}>
                  <strong>Статус акаунта:</strong>{' '}
                  <span className={`role-badge ${user.isBlocked ? 'badge-danger' : 'badge-active'}`}>
                    {user.isBlocked ? 'Заблоковано' : 'Активний'}
                  </span>
                </p>
                <p style={{ marginTop: '0.6rem' }}>
                  <strong>Двофакторна автентифікація (2FA):</strong>{' '}
                  <span className={`role-badge ${user.twoFactorEnabled ? 'badge-active' : 'sm-btn-secondary'}`}>
                    {user.twoFactorEnabled ? 'Увімкнено (Email OTP)' : 'Вимкнено'}
                  </span>
                </p>
                <p style={{ marginTop: '0.6rem' }}>
                  <strong>ID користувача:</strong> <code className="code-text">{user.id}</code>
                </p>
              </div>

              <div style={{ backgroundColor: '#3d2c29', padding: '1rem', borderRadius: '8px', marginBottom: '1.25rem', border: '1px solid #7c5e58' }}>
                <h4 style={{ margin: '0 0 0.5rem 0', color: '#fffbfa' }}>🛡️ Двофакторна безпека (2FA)</h4>
                <p style={{ fontSize: '0.85rem', color: '#eadbd8', margin: '0 0 0.8rem 0' }}>
                  При увімкненій опції під час кожного входу на вашу пошту надсилатиметься одноразовий 6-значний код безпеки (OTP).
                </p>
                <button
                  type="button"
                  onClick={handleToggleTwoFactor}
                  disabled={!user.isActive}
                  className={`sm-btn ${user.twoFactorEnabled ? 'sm-btn-danger' : 'sm-btn-success'}`}
                  style={{ padding: '8px 16px', fontSize: '0.85rem' }}
                >
                  {user.twoFactorEnabled ? 'Вимкнути 2FA' : 'Увімкнути 2FA (Email OTP)'}
                </button>
              </div>

              {!user.isActive && (
                <div style={{ backgroundColor: '#4a3430', padding: '1rem', borderRadius: '8px', border: '1px solid #d4a373', marginBottom: '1.25rem' }}>
                  <p style={{ margin: '0 0 0.6rem 0', fontSize: '0.85rem', color: '#ffdeb8' }}>
                    ⚠️ Ваш обліковий запис ще не активовано через email. Перевірте скриньку або надішліть новий лист:
                  </p>
                  <button
                    type="button"
                    onClick={handleResendActivation}
                    className="secondary-btn"
                  >
                    📩 Надіслати лист активації ще раз
                  </button>
                </div>
              )}

              {!isAdmin && (
                <div style={{ backgroundColor: '#4a3430', padding: '0.8rem', borderRadius: '8px', fontSize: '0.85rem', color: '#eadbd8', border: '1px solid #7c5e58' }}>
                  ℹ️ Згідно з політикою безпеки (RBAC), ви маєте права звичайного користувача та маєте доступ лише до власного профілю.
                </div>
              )}
            </div>
          )}

          {isAdmin && activeTab === 'users' && (
            <div>
              <div className="section-header">
                <h3 className="section-title">Список користувачів системи</h3>
                <button
                  type="button"
                  onClick={fetchAdminUsers}
                  className="secondary-btn"
                  disabled={adminLoading}
                >
                  {adminLoading ? 'Оновлення...' : '🔄 Оновити'}
                </button>
              </div>

              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Email</th>
                      <th>Роль</th>
                      <th>Активація</th>
                      <th>Статус</th>
                      <th>Дії (Блокування / Роль)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {adminUsers.map((u) => {
                      const isSelf = u.id === user.id;
                      return (
                        <tr key={u.id}>
                          <td>
                            <strong>{u.email}</strong> {isSelf && <span style={{ color: '#bc875f', fontSize: '0.75rem' }}>(Ви)</span>}
                          </td>
                          <td>
                            <span className={`role-badge ${u.role === 'Admin' ? 'badge-admin' : ''}`}>
                              {u.role}
                            </span>
                          </td>
                          <td>
                            <span className={`role-badge ${u.isActive ? 'badge-active' : 'badge-warning'}`}>
                              {u.isActive ? 'Активовано' : 'Очікує'}
                            </span>
                          </td>
                          <td>
                            {u.isBlocked ? (
                              <span className="role-badge badge-danger">Заблоковано (Ручне)</span>
                            ) : u.isLockedOut ? (
                              <span className="role-badge badge-danger" title={`Блокування до: ${new Date(u.lockoutEnd).toLocaleTimeString()}`}>
                                Заблоковано (Brute Force)
                              </span>
                            ) : (
                              <span className="role-badge badge-active">Активний</span>
                            )}
                            {u.failedLoginAttempts > 0 && !u.isBlocked && !u.isLockedOut && (
                              <div style={{ fontSize: '0.75rem', color: '#fbbf24', marginTop: '3px' }}>
                                Спроб: {u.failedLoginAttempts}/5
                              </div>
                            )}
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: '6px' }}>
                              <button
                                type="button"
                                disabled={isSelf}
                                onClick={() => toggleBlockUser(u.id)}
                                className={`sm-btn ${u.isBlocked || u.isLockedOut ? 'sm-btn-success' : 'sm-btn-danger'}`}
                                style={{ opacity: isSelf ? 0.4 : 1, cursor: isSelf ? 'not-allowed' : 'pointer' }}
                                title={isSelf ? 'Не можна заблокувати себе' : ''}
                              >
                                {u.isBlocked || u.isLockedOut ? 'Розблокувати' : 'Заблокувати'}
                              </button>
                              <button
                                type="button"
                                disabled={isSelf}
                                onClick={() => toggleRoleUser(u.id)}
                                className="sm-btn sm-btn-secondary"
                                style={{ opacity: isSelf ? 0.4 : 1, cursor: isSelf ? 'not-allowed' : 'pointer' }}
                                title={isSelf ? 'Не можна змінити власну роль' : 'Змінити роль User/Admin'}
                              >
                                Роль: {u.role === 'Admin' ? 'Зробити User' : 'Зробити Admin'}
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {isAdmin && activeTab === 'logs' && (
            <div>
              <div className="section-header">
                <h3 className="section-title">Журнал спроб входу користувачів</h3>
                <button
                  type="button"
                  onClick={fetchAdminLogs}
                  className="secondary-btn"
                  disabled={adminLoading}
                >
                  {adminLoading ? 'Оновлення...' : '🔄 Оновити'}
                </button>
              </div>

              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Час (UTC)</th>
                      <th>Email</th>
                      <th>IP-адреса</th>
                      <th>Результат</th>
                      <th>Деталі</th>
                    </tr>
                  </thead>
                  <tbody>
                    {adminLogs.length === 0 ? (
                      <tr>
                        <td colSpan="5" style={{ textAlign: 'center', padding: '1rem', color: '#d6c2be' }}>
                          Записів у журналі поки що немає.
                        </td>
                      </tr>
                    ) : (
                      adminLogs.map((log) => (
                        <tr key={log.id}>
                          <td>{new Date(log.timestamp.endsWith('Z') ? log.timestamp : log.timestamp + 'Z').toLocaleString('uk-UA', { timeZone: 'UTC' })}</td>
                          <td><strong>{log.email}</strong></td>
                          <td><code>{log.ipAddress || '—'}</code></td>
                          <td>
                            <span className={`role-badge ${log.isSuccess ? 'badge-active' : 'badge-danger'}`}>
                              {log.isSuccess ? 'Успішно' : 'Невдало'}
                            </span>
                          </td>
                          <td style={{ color: '#eadbd8' }}>{log.details}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // ВАРІАНТ 2: ЕКРАН ДВОЕТАПНОЇ ПЕРЕВІРКИ (2FA)
  if (authMode === 'twoFactor') {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <h2 className="auth-title">🔒 Двоетапна перевірка</h2>
          <p style={{ fontSize: '0.9rem', color: '#eadbd8', textAlign: 'center', marginBottom: '1.25rem' }}>
            На адресу <strong>{twoFactorEmail}</strong> надіслано 6-значний код безпеки. Введіть його нижче:
          </p>

          {message && <div className="success-box">{message}</div>}
          {error && <div className="error-box">{error}</div>}

          <form onSubmit={handleVerifyTwoFactor}>
            <div className="input-group">
              <label className="input-label" style={{ textAlign: 'center' }}>Код безпеки (6 цифр)</label>
              <input
                type="text"
                maxLength="6"
                value={twoFactorCode}
                onChange={(e) => setTwoFactorCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                required
                className="auth-input"
                style={{ textAlign: 'center', fontSize: '1.4rem', letterSpacing: '6px', fontWeight: 'bold' }}
                autoFocus
              />
            </div>

            <button type="submit" className="primary-btn" disabled={loading || twoFactorCode.length < 6}>
              {loading ? 'Перевірка...' : 'Підтвердити та увійти'}
            </button>

            <button
              type="button"
              onClick={() => { setAuthMode('login'); setError(''); setMessage(''); }}
              className="switch-btn"
            >
              ← Повернутися до входу
            </button>
          </form>
        </div>
      </div>
    );
  }

  // ВАРІАНТ 3: ВСТАНОВЛЕННЯ НОВОГО ПАРОЛЯ ЧЕРЕЗ ТОКЕН
  if (authMode === 'reset') {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <h2 className="auth-title">Встановлення нового пароля</h2>

          {message && <div className="success-box">{message}</div>}
          {error && <div className="error-box">{error}</div>}

          <form onSubmit={handleResetPasswordSubmit}>
            <div className="input-group">
              <label className="input-label">Новий пароль</label>
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Введіть новий пароль"
                  required
                  className="auth-input"
                  style={{ paddingRight: '42px' }}
                />
                {renderEyeIcon()}
              </div>

              {password.length > 0 && (
                <div className="strength-container">
                  <div className="strength-bar-bg">
                    <div
                      className="strength-bar-fill"
                      style={{
                        width: `${(strengthInfo.score / 5) * 100}%`,
                        backgroundColor: strengthInfo.color
                      }}
                    />
                  </div>
                  <span className="strength-text" style={{ color: strengthInfo.color }}>
                    {strengthInfo.label}
                  </span>
                </div>
              )}
            </div>

            <div className="input-group">
              <label className="input-label">Підтвердження нового пароля</label>
              <input
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Повторіть новий пароль"
                required
                className="auth-input"
              />
            </div>

            <button type="submit" className="primary-btn" disabled={loading}>
              {loading ? 'Збереження...' : 'Зберегти новий пароль'}
            </button>

            <button
              type="button"
              onClick={() => { setAuthMode('login'); setError(''); setMessage(''); }}
              className="switch-btn"
            >
              ← Повернутися до входу
            </button>
          </form>
        </div>
      </div>
    );
  }

  // ВАРІАНТ 4: ЗАПИТ НА ВІДНОВЛЕННЯ ПАРОЛЯ
  if (authMode === 'forgot') {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <h2 className="auth-title">Відновлення пароля</h2>
          <p style={{ fontSize: '0.875rem', color: '#eadbd8', textAlign: 'center', marginBottom: '1.25rem' }}>
            Вкажіть адресу електронної пошти, і ми надішлемо посилання для відновлення доступу.
          </p>

          {message && <div className="success-box">{message}</div>}
          {error && <div className="error-box">{error}</div>}

          <form onSubmit={handleForgotPasswordSubmit}>
            <div className="input-group">
              <label className="input-label">Електронна пошта (Email)</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="example@gmail.com"
                required
                className="auth-input"
              />
            </div>

            <button type="submit" className="primary-btn" disabled={loading}>
              {loading ? 'Надсилання...' : 'Надіслати лист для відновлення'}
            </button>

            <button
              type="button"
              onClick={() => { setAuthMode('login'); setError(''); setMessage(''); }}
              className="switch-btn"
            >
              ← Повернутися до входу
            </button>
          </form>
        </div>
      </div>
    );
  }

  // ВАРІАНТ 5: ФОРМИ ВХОДУ ТА РЕЄСТРАЦІЇ
  const isRegister = authMode === 'register';

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="nav-tabs">
          <button
            type="button"
            onClick={() => { setAuthMode('register'); setError(''); setMessage(''); if (!isRegister) loadCaptcha(); }}
            className={`tab-button ${isRegister ? 'active' : ''}`}
          >
            Реєстрація
          </button>
          <button
            type="button"
            onClick={() => { setAuthMode('login'); setError(''); setMessage(''); }}
            className={`tab-button ${!isRegister ? 'active' : ''}`}
          >
            Вхід
          </button>
        </div>

        <h2 className="auth-title">{isRegister ? 'Створення акаунта' : 'Вхід у систему'}</h2>

        {message && <div className="success-box">{message}</div>}
        {error && <div className="error-box">{error}</div>}

        <form onSubmit={handleAuthSubmit}>
          <div className="input-group">
            <label className="input-label">Електронна пошта</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="example@gmail.com"
              required
              className="auth-input"
            />
          </div>

          <div className="input-group">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <label className="input-label" style={{ margin: 0 }}>Пароль</label>
              {!isRegister && (
                <button
                  type="button"
                  onClick={() => { setAuthMode('forgot'); setError(''); setMessage(''); }}
                  className="link-btn"
                >
                  Забули пароль?
                </button>
              )}
            </div>

            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="auth-input"
                style={{ paddingRight: '42px' }}
              />
              {renderEyeIcon()}
            </div>

            {isRegister && password.length > 0 && (
              <div className="strength-container">
                <div className="strength-bar-bg">
                  <div
                    className="strength-bar-fill"
                    style={{
                      width: `${(strengthInfo.score / 5) * 100}%`,
                      backgroundColor: strengthInfo.color
                    }}
                  />
                </div>
                <span className="strength-text" style={{ color: strengthInfo.color }}>
                  {strengthInfo.label}
                </span>
              </div>
            )}
          </div>

          {isRegister && (
            <div className="input-group">
              <label className="input-label" htmlFor="captchaCode">Код CAPTCHA</label>
              <div className="captcha-row">
                <div className="captcha-preview" aria-busy={captchaLoading}>
                  {captcha && <img src={captcha.image} alt="П’ятисимвольний код CAPTCHA" width="180" height="56" />}
                  {captchaLoading && <span>Завантаження…</span>}
                  {captchaError && <span role="alert">{captchaError}</span>}
                </div>
                <button type="button" className="secondary-btn captcha-refresh" onClick={loadCaptcha} disabled={captchaLoading || loading}>
                  Новий код
                </button>
              </div>
              <input id="captchaCode" className="auth-input" value={captchaCode}
                onChange={(e) => setCaptchaCode(e.target.value.toUpperCase())}
                autoComplete="off" maxLength={5} disabled={!captcha} required />
            </div>
          )}

          <button type="submit" className="primary-btn" disabled={loading || (isRegister && (!captcha || captchaCode.trim().length !== 5))}>
            {loading ? 'Обробка...' : (isRegister ? 'Зареєструватися' : 'Увійти')}
          </button>
        </form>

        <div style={{ display: 'flex', alignItems: 'center', margin: '1.25rem 0 1rem 0' }}>
          <div style={{ flex: 1, height: '1px', backgroundColor: '#7c5e58' }}></div>
          <span style={{ padding: '0 10px', fontSize: '0.78rem', color: '#d6c2be', fontWeight: '500' }}>
            або OpenID Connect
          </span>
          <div style={{ flex: 1, height: '1px', backgroundColor: '#7c5e58' }}></div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'center', minHeight: '44px' }}>
          <div id="googleSignInBtn"></div>
        </div>
      </div>
    </div>
  );
}
