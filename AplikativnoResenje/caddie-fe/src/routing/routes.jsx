import App from '../App';
import ChangePasswordComponent from '../components/ChangePasswordComponent';
import FileUploadComponent from '../components/FileUploadComponent';
import React from 'react';


export const routes= [
  {
    path: '/',
    element: <App/>,
    children: [
      {
        path: '/file-upload',
        element: <FileUploadComponent />,
      },
      {
        path: '/change-password',
        element: <ChangePasswordComponent/>
      }
    ],
  },
];
