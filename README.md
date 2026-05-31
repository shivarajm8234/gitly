# Gitly

Gitly is an AI-powered GitHub Secret Scanner designed to quickly and efficiently scan repositories for exposed credentials, high-entropy strings, and potential security risks.

## Features

- **Fast & Deep Scanning**: Choose between quick and deep scanning modes.
- **Real-time Feedback**: Live progress monitoring and streaming of findings using Server-Sent Events (SSE).
- **Comprehensive Detection**: Identifies a wide range of exposed secrets, including API keys, tokens, and passwords.
- **Detailed Findings**: View affected files, lines of code, and remediation steps.
- **Commit History Analysis**: Option to scan historical commits in addition to the latest codebase.
- **Export Options**: Download scan reports in JSON, CSV, or PDF formats.

## Architecture

Gitly consists of two main components:
1. **Frontend**: A modern, single-page application built with HTML, CSS, and vanilla JavaScript, interacting with the backend via REST API and SSE.
2. **Backend**: A Node.js Express server that handles GitHub API interactions, implements the secret scanning logic, and manages streaming data to the client.

## Getting Started

### Prerequisites

- Node.js (v18 or higher recommended)
- A GitHub Personal Access Token (PAT) for scanning private repositories and avoiding rate limits.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/shivarajm8234/gitly.git
   cd gitly
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure Environment Variables:
   - Copy `.env.example` to `.env`
   - Add your `GITHUB_TOKEN` to the `.env` file.

4. Start the server:
   ```bash
   npm start
   ```

5. Open `http://localhost:3000` in your browser.

## Usage

1. **Authenticate**: Access is restricted. Provide an authorized email address to log in.
2. **Scan**: Enter a GitHub repository URL and click "Start Scan".
3. **Review**: Examine the dashboard for detected secrets, categorized by severity (Critical, High, Medium, Low, Info).
4. **Remediate**: Follow the suggested remediation steps for any exposed keys.

## Deployment

To deploy the full application (frontend + backend), you need a hosting provider that supports Node.js, such as Render, Heroku, or Vercel. 

**Note on Firebase Deployment:** Firebase Hosting is designed for static assets. To deploy the backend on Firebase, you must convert the Express server (`server.js`) into a Firebase Cloud Function.

## License

MIT License
