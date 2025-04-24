import { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { setTokens } from '../utils/Auth';

const AuthCallback = () => {
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const handleAuthCallback = async () => {
      try {
        const params = new URLSearchParams(location.search);
        const username = params.get('username');
        const email = params.get('email');
        const accessToken = params.get('access_token');
        const refreshToken = params.get('refresh_token');
        const accessTokenExpire = params.get('expire_time');
        const refreshTokenExpire = params.get('refresh_expire_time');
        
        if (!username || !email || !accessToken || !refreshToken || !accessTokenExpire || !refreshTokenExpire) {
          throw new Error('Brak wymaganych danych w odpowiedzi autoryzacyjnej.');
        }

        setTokens(
          username,
          email,
          accessToken,
          refreshToken, 
          accessTokenExpire,
          refreshTokenExpire
        );

        console.log('Zalogowano pomyślnie za pomocą sociali.');
        navigate('/home', { replace: true });
      } catch (error) {
        console.error('Błąd podczas przetwarzania parametrów autoryzacji: ', error);
        navigate('/login', { replace: true });
      } finally {
        setLoading(false);
      }
    };

    handleAuthCallback();
  }, [location, navigate]);

  if (loading) {
    return <div className="flex justify-center items-center h-screen">Trwa logowanie za pomocą sociali...</div>;
  }

  return null;
};

export default AuthCallback;