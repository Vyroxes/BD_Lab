import { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { setTokens } from '../utils/Auth';

const AuthCallback = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const handleAuthCallback = async () => {
      try {
        const params = new URLSearchParams(location.search);
        const accessToken = params.get('access_token');
        const refreshToken = params.get('refresh_token');
        const username = params.get('username');

        if (!accessToken || !refreshToken) {
          throw new Error('Brak wymaganych tokenów w odpowiedzi autoryzacyjnej');
        }

        const accessTokenExpire = "00:00:10:00";
        const refreshTokenExpire = "01:00:00:00";

        setTokens(
          accessToken,
          refreshToken, 
          accessTokenExpire,
          refreshTokenExpire,
          username
        );

        console.log('Autoryzacja zakończona pomyślnie');
        navigate('/home', { replace: true });
      } catch (err) {
        console.error('Błąd podczas przetwarzania parametrów autoryzacji:', err);
        setError('Wystąpił błąd podczas logowania. Spróbuj ponownie.');
        navigate('/login', { replace: true });
      } finally {
        setLoading(false);
      }
    };

    handleAuthCallback();
  }, [location, navigate]);

  if (loading) {
    return <div className="flex justify-center items-center h-screen">Trwa logowanie...</div>;
  }

  if (error) {
    return <div className="flex justify-center items-center h-screen text-red-500">{error}</div>;
  }

  return null;
};

export default AuthCallback;