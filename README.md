\# Portfolio 01: Security Monitoring (Graylog SIEM)



This repository contains our Security Monitoring lab setup for the Cyber Security Automation module.



\## ✅ Goal

Deploy a centralized SIEM prototype using \*\*Graylog\*\* for:

\- Log collection and analysis

\- Dashboards for monitoring

\- Alerting and correlation rules

\- Automated reporting (Python)



\## ✅ Current Status (Stage 1 Complete)

We have successfully deployed the SIEM stack using Docker Compose:



\- Graylog (SIEM UI)

\- OpenSearch (log storage + search engine)

\- MongoDB (Graylog configuration database)



Graylog is accessible at:

http://127.0.0.1:9000



\## 🧱 Tech Stack

\- Graylog: `graylog/graylog:6.1`

\- MongoDB: `mongo:7`

\- OpenSearch: `opensearchproject/opensearch:2.15.0`



\## 🚀 How to Run (Team Setup)

\### 1) Clone the repo

```bash

git clone <REPO\_URL>

cd graylog-lab



