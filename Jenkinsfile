pipeline {
    agent any

    // ─────────────────────────────────────────────────────────────────────────
    // Environment Variables
    //
    // BUILD_NUMBER is appended to network and container names so that
    // multiple concurrent pipeline runs never collide.
    //
    // Required Jenkins credentials:
    //   - "groq-api-key"  : Secret text  → Groq API key
    //   - "github-token"  : Secret text  → GitHub PAT with repo + issues scope
    //
    // Pre-existing environment variable:
    //   - HOST_JENKINS_HOME : host-side path of the Jenkins container home dir
    //                         (e.g. /home/user/jenkins_home)
    //                         Used to compute the correct -v mount path.
    // ─────────────────────────────────────────────────────────────────────────
    environment {
        NET_NAME     = "devsecops-net-${BUILD_NUMBER}"
        DVWA_NAME    = "dvwa-${BUILD_NUMBER}"
        GROQ_API_KEY = credentials('groq-api-key')
        GITHUB_TOKEN = credentials('github-token')
        GITHUB_REPO  = 'Yaman-Turkoz/Jenkins-Test'
    }

    options {
        skipDefaultCheckout(true)
    }

    stages {

        // ─────────────────────────────────────────────────────────────────────
        stage('Clean Workspace') {
            steps { deleteDir() }
        }

        // ─────────────────────────────────────────────────────────────────────
        stage('Checkout') {
            steps { checkout scm }
        }

        // ─────────────────────────────────────────────────────────────────────
        // SAST — Existing Semgrep stage (unchanged)
        // ─────────────────────────────────────────────────────────────────────
        stage('Semgrep Scan') {
            steps {
                script {
                    // Translate the in-container workspace path to its
                    // host-side equivalent. Without this the -v mount fails.
                    def hostWorkspace = env.WORKSPACE.replace(
                        '/var/jenkins_home',
                        env.HOST_JENKINS_HOME
                    )

                    sh """
                        docker run --rm \\
                            -v ${hostWorkspace}:/src \\
                            semgrep/semgrep \\
                            semgrep scan /src \\
                            --config=/src/semgrep-rules/xss.yaml \\
                            --json > semgrep-report.json
                    """

                    def reportText = readFile('semgrep-report.json').trim()
                    if (!reportText) error("Semgrep report is empty — scan may have failed.")

                    def report   = new groovy.json.JsonSlurper().parseText(reportText)
                    def findings = report.results.size()

                    if (findings > 0) {
                        echo "Semgrep: ${findings} security finding(s) detected!"
                        error("Semgrep findings present — stopping pipeline.")
                    } else {
                        echo "Semgrep: No findings."
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // DAST Stage 1: Start and prepare DVWA
        //
        // Steps:
        //   1. Create a build-specific Docker network
        //   2. Start the DVWA container on that network
        //   3. Wait until DVWA responds with HTTP 200/302 (max ~2 minutes)
        //   4. Set default_security_level to "low" in the DVWA PHP config
        //      → ZAP's session starts at "low" security
        //      → XSS cannot be found in "impossible" mode; the test would be pointless
        //   5. Initialize the DB, log in, and confirm the security level via curl
        // ─────────────────────────────────────────────────────────────────────
        stage('DAST: Start DVWA') {
            steps {
                script {

                    // 1. Create the Docker network
                    sh "docker network create ${NET_NAME}"

                    // 2. Start the DVWA container on that network.
                    //    Container name is unique per build number.
                    sh """
                        docker run -d \\
                            --name ${DVWA_NAME} \\
                            --network ${NET_NAME} \\
                            vulnerables/web-dvwa
                    """

                    // 3. Wait until DVWA is ready to serve HTTP.
                    //    A curlimages/curl container on the same network can
                    //    reach DVWA by container name (Docker DNS resolution).
                    sh """
                        docker run --rm \\
                            --network ${NET_NAME} \\
                            curlimages/curl:latest \\
                            sh -c '
                                echo "=== Waiting for DVWA... ==="
                                for i in \$(seq 1 40); do
                                    STATUS=\$(curl -so /dev/null -w "%{http_code}" \\
                                        http://${DVWA_NAME}/ 2>/dev/null || echo "000")
                                    if [ "\$STATUS" = "200" ] || [ "\$STATUS" = "302" ]; then
                                        echo "DVWA is ready! (attempt \$i, HTTP \$STATUS)"
                                        exit 0
                                    fi
                                    echo "Attempt \$i: HTTP \$STATUS — waiting 3s..."
                                    sleep 3
                                done
                                echo "ERROR: DVWA did not start within 120 seconds!" >&2
                                exit 1
                            '
                    """

                    // 4. Set default_security_level to "low" in the DVWA PHP config.
                    //    We run sed inside the container via docker exec.
                    //    Original line example:
                    //      $_DVWA[ 'default_security_level' ] = 'impossible';
                    //    Target:
                    //      $_DVWA[ 'default_security_level' ] = 'low';
                    //
                    //    NOTE: PHP reads the config on every request,
                    //          no Apache/PHP-FPM restart needed.
                    sh """docker exec ${DVWA_NAME} sed -i "s/default_security_level' ] = '[^']*'/default_security_level' ] = 'low'/" /var/www/html/config/config.inc.php 2>/dev/null || true"""

                    // 5. Initialize the DB, log in, and confirm security level.
                    //    All steps run in a single curl container using a cookie jar.
                    sh """
                        docker run --rm \\
                            --network ${NET_NAME} \\
                            curlimages/curl:latest \\
                            sh -c '
                                echo "--- DB init ---"
                                # GET setup page (initialize cookie jar)
                                curl -sf -c /tmp/jar.txt \\
                                    http://${DVWA_NAME}/setup.php -o /dev/null
                                # Create the database
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    -X POST http://${DVWA_NAME}/setup.php \\
                                    -d "create_db=Create+%2F+Reset+Database" \\
                                    -o /dev/null
                                echo "DB init done."

                                echo "--- Login ---"
                                # GET login page (fetch CSRF token)
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    http://${DVWA_NAME}/login.php -o /dev/null
                                # POST login
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    -X POST http://${DVWA_NAME}/login.php \\
                                    -d "username=admin&password=password&Login=Login" \\
                                    -L -o /dev/null
                                echo "Login done."

                                echo "--- Security = low ---"
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    -X POST http://${DVWA_NAME}/security.php \\
                                    -d "seclev_submit=Submit&security=low" \\
                                    -L -o /dev/null
                                echo "Security level set to low."
                            '
                    """

                    echo "DVWA is ready and configured."
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // DAST Stage 2: ZAP XSS scan
        //
        // The ZAP Automation Framework YAML is generated at runtime because
        // DVWA_NAME changes with each build number.
        //
        // Scan strategy:
        //   - Spider: crawls DVWA pages (authenticated)
        //   - Active Scan: ONLY XSS rules (40012, 40014, 40016, 40017)
        //     defaultStrength: disabled → all unlisted rules are turned off
        //     Only the 4 rules above run; 100+ others are skipped
        //     → lower false-positive rate, faster scan
        //
        // Authentication:
        //   - ZAP opens its own session via a form POST to login.php
        //   - Because default_security_level=low was set in the previous stage,
        //     ZAP's session also starts at "low" security
        // ─────────────────────────────────────────────────────────────────────
        stage('DAST: ZAP XSS Scan') {
            steps {
                script {
                    def hostWorkspace = env.WORKSPACE.replace(
                        '/var/jenkins_home',
                        env.HOST_JENKINS_HOME
                    )

                    // Write the ZAP Automation Framework YAML to the workspace
                    writeFile file: 'zap-automation.yaml', text: """---
env:
  contexts:
  - name: dvwa
    urls:
    - "http://${DVWA_NAME}/"
    includePaths:
    - "http://${DVWA_NAME}/.*"
    excludePaths:
    - "http://${DVWA_NAME}/logout.php"
    - "http://${DVWA_NAME}/setup.php"
    authentication:
      method: form
      parameters:
        loginPageUrl: "http://${DVWA_NAME}/login.php"
        loginRequestData: "username={%username%}&password={%password%}&Login=Login"
      verification:
        method: response
        loggedInRegex: "(?i)(welcome|logout|dvwa security)"
        loggedOutRegex: "(?i)(login|sign in)"
    sessionManagement:
      method: cookie
    users:
    - name: admin
      credentials:
        username: "admin"
        password: "password"
  parameters:
    failOnError: false
    failOnWarning: false
    progressToStdout: true

jobs:
- type: spider
  parameters:
    context: dvwa
    user: admin
    url: "http://${DVWA_NAME}/"
    maxDuration: 3
    maxChildren: 30
    acceptCookies: true

- type: activeScan
  parameters:
    context: dvwa
    user: admin
    maxRuleDurationInMins: 10
    maxScanDurationInMins: 20
  policyDefinition:
    # defaultStrength: disabled → all unlisted rules are turned off
    # Only the XSS rules below are active, reducing false positives
    defaultStrength: disabled
    defaultThreshold: off
    rules:
    - id: 40012
      name: "Cross Site Scripting (Reflected)"
      strength: high
      threshold: medium
    - id: 40014
      name: "Cross Site Scripting (Persistent)"
      strength: high
      threshold: medium
    - id: 40016
      name: "Cross Site Scripting (Persistent) - Prime"
      strength: high
      threshold: medium
    - id: 40017
      name: "Cross Site Scripting (Persistent) - Spider"
      strength: high
      threshold: medium

- type: report
  parameters:
    template: traditional-json
    reportDir: "/zap/wrk"
    reportFile: "zap-report"
    reportTitle: "ZAP XSS Scan - DVWA"
    reportDescription: "Jenkins DAST Pipeline - Build ${BUILD_NUMBER}"
"""

                    // Run the ZAP container
                    //   --network ${NET_NAME}       → can reach DVWA by container name
                    //   -v hostWorkspace:/zap/wrk   → reads YAML, writes report here
                    //   || true                     → ZAP exits 1 when findings exist; don't stop pipeline
                    sh """
                        docker run --rm \\
                            --network ${NET_NAME} \\
                            -v ${hostWorkspace}:/zap/wrk/:rw \\
                            ghcr.io/zaproxy/zaproxy:stable \\
                            zap.sh -cmd -autorun /zap/wrk/zap-automation.yaml \\
                        || true
                    """

                    // Report file check.
                    // ZAP traditional-json template → reportFile + ".json" = zap-report.json
                    if (!fileExists('zap-report.json')) {
                        echo "WARNING: zap-report.json not found. Creating empty report."
                        writeFile file: 'zap-report.json', text: '{"site":[]}'
                    }

                    def zapReport = new groovy.json.JsonSlurper().parseText(
                        readFile('zap-report.json')
                    )
                    def totalAlerts = zapReport.site?.collectMany { it.alerts ?: [] }?.size() ?: 0
                    echo "ZAP scan complete — ${totalAlerts} alert(s) found."
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // DAST Stage 3: AI validation and GitHub Issue
        //
        // This stage is the Jenkins pipeline equivalent of the
        // ai_analyze.py + create_issues.py pair used in the workflow.
        //
        // scripts/zap_analyze.py:
        //   1. Extracts XSS findings from zap-report.json
        //   2. Asks the Groq LLM for each finding: true or false positive?
        //   3. Writes all true positives with their PoCs into a single GitHub Issue
        //   4. Saves the full results to zap-analysis.json
        //
        // Why python:3.11-slim container?
        //   The requests library may not be installed in the Jenkins container.
        //   A Docker container provides a clean, reproducible environment.
        //
        // Why --network host?
        //   The Python script needs internet access to reach the Groq and GitHub APIs.
        //   devsecops-net is an internal-only network with no internet egress.
        // ─────────────────────────────────────────────────────────────────────
        stage('DAST: AI Analysis & GitHub Issue') {
            steps {
                script {
                    def hostWorkspace = env.WORKSPACE.replace(
                        '/var/jenkins_home',
                        env.HOST_JENKINS_HOME
                    )

                    sh """
                        docker run --rm \\
                            --network host \\
                            -v ${hostWorkspace}:/workspace \\
                            -e GROQ_API_KEY=${GROQ_API_KEY} \\
                            -e GITHUB_TOKEN=${GITHUB_TOKEN} \\
                            -e GITHUB_REPO=${GITHUB_REPO} \\
                            python:3.11-slim \\
                            sh -c '
                                pip install requests --quiet --no-cache-dir
                                python3 /workspace/scripts/zap_analyze.py \\
                                    --report /workspace/zap-report.json \\
                                    --output /workspace/zap-analysis.json
                            '
                    """
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Post Actions — Runs on every outcome (success, failure, abort)
    //
    // Without cleanup, DVWA containers and networks accumulate on the host.
    // "|| true" → silently skip if the resource does not exist.
    // ─────────────────────────────────────────────────────────────────────────
    post {
        always {
            sh """
                echo "=== Cleanup ==="
                docker stop ${DVWA_NAME} 2>/dev/null || true
                docker rm   ${DVWA_NAME} 2>/dev/null || true
                docker network rm ${NET_NAME} 2>/dev/null || true
                echo "DVWA container and network removed."
            """
            archiveArtifacts(
                artifacts: 'semgrep-report.json,zap-report.json,zap-automation.yaml,zap-analysis.json',
                allowEmptyArchive: true
            )
        }
    }
}
