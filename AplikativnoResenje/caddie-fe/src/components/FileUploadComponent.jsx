import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { toast } from 'react-toastify';

const FileUploadComponent = () => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [files, setFiles] = useState([]);

  useEffect(() => {
    fetchFiles();
  }, []);

  const fetchFiles = async () => {
    try {
      const response = await axios.get(`${process.env.REACT_APP_BASE_URL}/aws`);
      setFiles(response.data);
      console.log(response.data)
    } catch (error) {
      console.error('Error fetching files:', error);
    }
  };

  const handleFileChange = (event) => {
    setSelectedFile(event.target.files[0]);
  };

  const handleUpload = async () => {
    try {
      const formData = new FormData();
      formData.append('image', selectedFile);
      await axios.post(`${process.env.REACT_APP_BASE_URL}/aws`, formData);
      toast.success('File uploaded successfully!', { position: toast.POSITION.TOP_RIGHT });
      fetchFiles();
    } catch (error) {
      toast.error('Error uploading file!', { position: toast.POSITION.TOP_RIGHT });
    }
  };

  const handleDownload = async (file) => {
    try {
      
      const blob = new Blob([file]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.Key;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } catch (error) {
      console.error('Error downloading file:', error);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', margin: '20px' }}>
      <input type="file" onChange={handleFileChange} style={{ padding: '10px', marginBottom: '10px' }} />
      <button
        onClick={handleUpload}
        style={{
          padding: '10px',
          backgroundColor: '#4caf50',
          color: '#fff',
          border: 'none',
          borderRadius: '5px',
          cursor: 'pointer',
          transition: 'background-color 0.3s',
        }}
        onMouseOver={(e) => (e.target.style.backgroundColor = '#45a049')}
        onMouseOut={(e) => (e.target.style.backgroundColor = '#4caf50')}
      >
        Upload
      </button>

      <div style={{ marginTop: '20px', width: '300px', textAlign: 'left' }}>
        <h2>Files</h2>
        <ul style={{ listStyle: 'none', padding: '0' }}>
          {files.map((file) => (
            <li
              key={file.Key}
              style={{
                marginBottom: '10px',
                padding: '10px',
                border: '1px solid #ddd',
                borderRadius: '5px',
                cursor: 'pointer',
                textDecoration: 'underline',
                color: 'blue',
              }}
              onClick={() => handleDownload(file)}
            >
              {file.Key}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default FileUploadComponent;