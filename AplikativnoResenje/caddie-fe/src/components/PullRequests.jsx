import { useState, useEffect, useMemo } from "react";

export const PullRequestsPage = () => {
  const [pullRequests, setPullRequests] = useState();

  const loadData = async () => {
    const response = await fetch("http://localhost:8000/prs");
    const data = await response.json();
    console.log(data);
    setPullRequests(data);
  };

  useEffect(() => {
    loadData();
  }, []);

  const html = useMemo(() => {
    return pullRequests?.map((pr) => (
      <div style={{ border: "1px solid black", marginBottom: "10px" }}>
        <p>Number: {pr.number}</p>
        <div
          dangerouslySetInnerHTML={{
            __html: `Title: ${pr.title}`,
          }}
        ></div>
        <p>Body: {pr.body}</p>
        <p>GithubId: {pr.githubId}</p>
      </div>
    ));
  }, [pullRequests]);

  return <div>{html}</div>;
};
