import React, { useState } from 'react';
import { toast } from 'react-toastify';

const ChangePasswordComponent = () => {
  const [id, setId] = useState('');
  const [novaSifra, setNovaSifra] = useState('');

  const handleIdChange = (event) => {
    setId(event.target.value);
  };

  const handleNovaSifraChange = (event) => {
    setNovaSifra(event.target.value);
  };

  const handlePromeniSifru = () => {
    fetch(process.env.REACT_APP_BASE_URL + "/users/change-password", {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ id: id, nova_sifra: novaSifra }),
    })
      .then((response) => response.json())
      .then((data) => {
        toast.success('Uspešna promena lozinke!', { position: toast.POSITION.TOP_RIGHT });
      })
      .catch((error) =>  toast.error('Greska prilikom promene lozinke!', { position: toast.POSITION.TOP_RIGHT }));
  };

  return (
    <div style={styles.container}>
      <h1 style={styles.title}>Change Password</h1>
      <label style={styles.label}>
        User ID:
        <input type="text" value={id} onChange={handleIdChange} style={styles.input} />
      </label>
      <br />
      <label style={styles.label}>
        Nova šifra:
        <input type="password" value={novaSifra} onChange={handleNovaSifraChange} style={styles.input} />
      </label>
      <br />
      <button onClick={handlePromeniSifru} style={styles.button}>Promeni šifru</button>
    </div>
  );
};

const styles = {
  container: {
    width: '300px',
    margin: 'auto',
    marginTop: '40vh',
    transform: 'translateY(-50%)',
    padding: '20px',
    border: '1px solid #ccc',
    borderRadius: '5px',
    textAlign: 'center',
  },
  title: {
    fontSize: '24px',
    marginBottom: '20px',
  },
  label: {
    display: 'block',
    marginBottom: '10px',
  },
  input: {
    width: '100%',
    padding: '8px',
    fontSize: '16px',
    borderRadius: '5px',
    border: '1px solid #ccc',
  },
  button: {
    padding: '10px',
    fontSize: '16px',
    backgroundColor: '#4caf50',
    color: '#fff',
    border: 'none',
    borderRadius: '5px',
    cursor: 'pointer',
    transition: 'background-color 0.3s',
  },
};

export default ChangePasswordComponent;