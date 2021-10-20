#!/usr/bin/env sh

_() {
  REPO_NAME="espfa"
  COMMIT_DATE="2021-10-21T00:00:00"

  echo "GitHub Username: "
  read -r USERNAME
  echo "GitHub Personal Access Token: "
  read -r ACCESS_TOKEN

  [ -z "$USERNAME" ] && exit 1
  [ -z "$ACCESS_TOKEN" ] && exit 1

  # Create the repository
  curl -u "$USERNAME:$ACCESS_TOKEN" https://api.github.com/user/repos -d '{"name":"'"$REPO_NAME"'"}'

  # Initialize a new Git repository
  git init

  # Add all files and folders
  git add .

  # Commit with the desired commit date
  GIT_AUTHOR_DATE="$COMMIT_DATE" \
    GIT_COMMITTER_DATE="$COMMIT_DATE" \
    git commit -m "Upload files and folders"

  # Set the remote URL
  git remote add origin "https://github.com/$USERNAME/$REPO_NAME.git"

  # Push to the remote repository
  git push -u origin master

  echo
  echo "Files and folders uploaded to the repository: https://github.com/$USERNAME/$REPO_NAME"
} && _

unset -f _

