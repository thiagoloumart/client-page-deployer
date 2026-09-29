# Client Page Deployer

**Drag an HTML file, pick a name, and about a minute later `client.yourdomain.com/campaign` is live with HTTPS. No DNS panel, no SSH, no developer in the loop.**

## The problem

At a growth-marketing agency with 40–50 clients running at the same time, the team kept needing to put pages online: landing pages, campaign reports, proposals. Each one meant creating a DNS record, configuring nginx and issuing an SSL certificate. It was slow, it depended on the one person who knew how, and it was easy to get wrong.

## What it does

A small web app for the marketing team:

1. Log in, type the client name and a context (e.g. `acme` + `black-friday`), then drop the files (HTML plus its images, CSS and scripts).
2. The app creates the DNS record on Cloudflare, uploads the files to the server, writes the nginx config and issues the SSL certificate with certbot.
3. A live log shows every step. At the end you get the link: `https://acme.example.com/black-friday`.

It also keeps a history of everything published, and lets you edit, archive or delete a deployment, including its files on the server. There are separate admin and user accounts.

**In real use it published 57 client pages and reports** at the agency, with DNS and HTTPS set up automatically.

## Safety

Everything a user types ends up in a DNS record, a folder path or a server command, so the app validates all of it first:

- Client, context and file names only accept safe characters (letters, numbers, hyphen). Anything else is rejected before a single command runs.
- Users can only publish to the domains listed in `ALLOWED_DOMAINS`.
- Deleting files re-checks the stored path before removing anything.
- The app refuses to start without a real password and session secret. There are no default credentials.
- Passwords are hashed with bcrypt. Uploaded temp files are always cleaned up.

## Run it

```bash
npm install
cp .env.example .env   # fill in your server, Cloudflare zone and domain
npm start              # http://127.0.0.1:3000
```

Put it behind nginx with HTTPS (and ideally a VPN or SSO) before giving the team access. The target server needs nginx and certbot installed.

**Stack:** Node.js + Express, a single-page vanilla JS frontend, the Cloudflare API, SSH/SFTP (ssh2), nginx and certbot. The interface is in Portuguese.

## How it was built

AI-native: I wrote the spec from the agency's day-to-day and directed coding agents to build it. Then I hardened it before open-sourcing: the original trusted user input in server commands.

---

Thiago Lourenço Martins · [LinkedIn](https://www.linkedin.com/in/thiago-lourenco-martins) · [loumart.com.br](https://loumart.com.br)
