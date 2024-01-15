import { useState, useEffect, useMemo } from "react";
import { useParams } from "react-router-dom";

export const PullRequestsByUsernamePage = () => {
  const [pullRequests, setPullRequests] = useState([]);
  const { username = "" } = useParams();

  const loadData = async () => {
    if (username === "") return;
    const response = await fetch(
      `http://localhost:8000/prs/${username}/protected`,
      {
        headers: {
          Authorization:
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InN0amVwYW5vdmljc3JkamFuMjAwMEBnbWFpbC5jb20iLCJpYXQiOjE3MDUzMjc2MjEsImV4cCI6MTgwNTMyNzYyMX0.Zydg5rk3qGGqyHhHNTzn0i76Z8YuoCLcJT_AY6_Tcas",
        },
      }
    );
    if (response.status !== 200) return;
    const data = await response.json();
    console.log(data);
    setPullRequests(data);
  };

  useEffect(() => {
    loadData();
  }, [username]);

  const html = useMemo(() => {
    return pullRequests?.map((pr) => (
      <div style={{ border: "1px solid black", marginBottom: "10px" }}>
        <p>Author: {pr.author}</p>
        <p>Number: {pr.number}</p>
        <div>Title: {pr.title}</div>
        <p>Body: {pr.body}</p>
        <p>GithubId: {pr.githubId}</p>
      </div>
    ));
  }, [pullRequests]);

  return <div>{html}</div>;
};
