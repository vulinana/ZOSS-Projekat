import './App.css';
import { Outlet } from 'react-router-dom';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import HeaderComponent from './components/HeaderComponent';

function App() {
  return (
    <div className="App">
      <HeaderComponent></HeaderComponent>
       <Outlet></Outlet>
       <ToastContainer/>
    </div>
  );
}

export default App;
