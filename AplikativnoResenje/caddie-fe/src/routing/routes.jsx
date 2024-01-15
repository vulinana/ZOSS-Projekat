import App from "../App";
import ChangePasswordComponent from "../components/ChangePasswordComponent";
import FileUploadComponent from "../components/FileUploadComponent";
import React from "react";
import { PullRequestsPage } from "../components/PullRequests";
import { PullRequestsByUsernamePage } from "../components/PullRequestsUsername";

export const routes = [
  {
    path: "/",
    element: <App />,
    children: [
      {
        path: "/file-upload",
        element: <FileUploadComponent />,
      },
      {
        path: "/change-password",
        element: <ChangePasswordComponent />,
      },
      {
        path: "/pull-requests",
        element: <PullRequestsPage />,
      },
      {
        path: "/pull-requests/:username",
        element: <PullRequestsByUsernamePage />,
      },
    ],
  },
];
