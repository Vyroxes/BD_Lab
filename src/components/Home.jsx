import React from 'react';

import './Home.css';

const Home = () => {
    return (
        <div className='home-container'>
            <h1>Aplikacja do zarządzania kolekcją książek</h1>
            <h3>
                Ta aplikacja umożliwia zarządzanie wirtuaną biblioteką książek.
                Użytkownicy mogą dodawać książki ręcznie lub za pomocą kodu ISBN,
                przeglądać szczegóły książek, edytować oraz usuwać książki oraz
                przenosić je między kolekcją a listą życzeń. Dodatkowo, aplikacja
                pozwala na ocenianie i recenzowanie książek. To wygodne narzędzie do
                organizowania swojej wirtualnej biblioteki. O problemach należy
                informować przez formularz kontaktowy.
            </h3>
        </div>
    );
};

export default Home;