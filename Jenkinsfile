pipeline {
    agent any

    // ─────────────────────────────────────────────────────────────────────────
    // Ortam Değişkenleri
    //
    // BUILD_NUMBER her çalışmada benzersiz olduğu için network ve container
    // isimlerine ekliyoruz. Böylece birden fazla pipeline aynı anda çalışsa
    // çakışma olmaz.
    //
    // Jenkins'e eklenmesi gereken credential'lar:
    //   - "groq-api-key"  : Secret text  → Groq API anahtarı
    //   - "github-token"  : Secret text  → repo + issues yetkili GitHub PAT
    //
    // Zaten var olan ortam değişkeni:
    //   - HOST_JENKINS_HOME : Jenkins container'ının host'taki home dizini
    //                         (örn. /home/user/jenkins_home)
    //                         Volume mount yolunu hesaplamak için kullanılıyor.
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
        // SAST — Mevcut Semgrep aşaması (değiştirilmedi)
        // ─────────────────────────────────────────────────────────────────────
        stage('Semgrep Scan') {
            steps {
                script {
                    // Jenkins container içindeki workspace yolunu,
                    // host üzerindeki karşılığına çeviriyoruz.
                    // Bu dönüşüm olmadan -v mount çalışmaz.
                    def hostWorkspace = env.WORKSPACE.replace(
                        '/var/jenkins_home',
                        env.HOST_JENKINS_HOME
                    )

                    sh """
                        docker run --rm \\
                            -v ${hostWorkspace}:/src \\
                            -v /var/run/docker.sock:/var/run/docker.sock \\
                            semgrep/semgrep \\
                            semgrep scan /src \\
                            --config=/src/semgrep-rules/xss.yaml \\
                            --json > semgrep-report.json
                    """

                    def reportText = readFile('semgrep-report.json').trim()
                    if (!reportText) error("Semgrep raporu boş — tarama başarısız olmuş olabilir.")

                    def report   = new groovy.json.JsonSlurper().parseText(reportText)
                    def findings = report.results.size()

                    if (findings > 0) {
                        echo "Semgrep: ${findings} güvenlik bulgusu tespit edildi!"
                        error("Semgrep bulguları mevcut — pipeline durduruluyor.")
                    } else {
                        echo "Semgrep: Bulgu yok."
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // DAST Aşama 1: DVWA'yı ayağa kaldır ve hazırla
        //
        // Bu aşamada:
        //   1. Build'e özel Docker network oluşturulur
        //   2. DVWA container'ı bu network üzerinde başlatılır
        //   3. DVWA HTTP 200 dönene kadar beklenir (maks ~2 dakika)
        //   4. DVWA config dosyasında default security level "low" yapılır
        //      → ZAP kendi session'ını açtığında "low" security ile başlar
        //      → "impossible" modda XSS bulunamaz, test anlamsız olurdu
        //   5. Curl container ile DB init + güvenlik seviyesi doğrulanır
        // ─────────────────────────────────────────────────────────────────────
        stage('DAST: Start DVWA') {
            steps {
                script {

                    // 1. Docker network oluştur
                    sh "docker network create ${NET_NAME}"

                    // 2. DVWA container'ını başlat (aynı network üzerinde)
                    //    Container ismi build numarasıyla benzersiz.
                    sh """
                        docker run -d \\
                            --name ${DVWA_NAME} \\
                            --network ${NET_NAME} \\
                            vulnerables/web-dvwa
                    """

                    // 3. DVWA'nın HTTP cevap verebilir olmasını bekle
                    //    curlimages/curl container'ı aynı network üzerinden
                    //    DVWA'ya ulaşabilir (container adıyla DNS çözülür).
                    sh """
                        docker run --rm \\
                            --network ${NET_NAME} \\
                            curlimages/curl:latest \\
                            sh -c '
                                echo "=== DVWA bekleniyor... ==="
                                for i in \$(seq 1 40); do
                                    STATUS=\$(curl -so /dev/null -w "%{http_code}" \\
                                        http://${DVWA_NAME}/ 2>/dev/null || echo "000")
                                    if [ "\$STATUS" = "200" ] || [ "\$STATUS" = "302" ]; then
                                        echo "DVWA hazir! (deneme \$i, HTTP \$STATUS)"
                                        exit 0
                                    fi
                                    echo "Deneme \$i: HTTP \$STATUS — 3sn bekleniyor..."
                                    sleep 3
                                done
                                echo "HATA: DVWA 120 saniyede ayaga kalkmadi!" >&2
                                exit 1
                            '
                    """

                    // 4. DVWA config dosyasında default security level'ı "low" yap.
                    //    docker exec ile container içinde sed çalıştırıyoruz.
                    //    Orijinal satır örneği:
                    //      $_DVWA[ 'default_security_level' ] = 'impossible';
                    //    Hedef:
                    //      $_DVWA[ 'default_security_level' ] = 'low';
                    //
                    //    NOT: PHP config'i her request'te okunur,
                    //         Apache/PHP-FPM restart gerekmez.
                    sh """docker exec ${DVWA_NAME} sed -i "s/default_security_level' ] = '[^']*'/default_security_level' ] = 'low'/" /var/www/html/config/config.inc.php 2>/dev/null || true"""

                    // 5. DVWA veritabanını başlat + login + security doğrula
                    //    Tek bir curl container'ında cookie jar ile tüm adımlar:
                    sh """
                        docker run --rm \\
                            --network ${NET_NAME} \\
                            curlimages/curl:latest \\
                            sh -c '
                                echo "--- DB init ---"
                                # Setup sayfasına GET (cookie jar başlat)
                                curl -sf -c /tmp/jar.txt \\
                                    http://${DVWA_NAME}/setup.php -o /dev/null
                                # DB oluştur
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    -X POST http://${DVWA_NAME}/setup.php \\
                                    -d "create_db=Create+%2F+Reset+Database" \\
                                    -o /dev/null
                                echo "DB init tamamlandi."

                                echo "--- Login ---"
                                # Login sayfasına GET (CSRF token için)
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    http://${DVWA_NAME}/login.php -o /dev/null
                                # Login POST
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    -X POST http://${DVWA_NAME}/login.php \\
                                    -d "username=admin&password=password&Login=Login" \\
                                    -L -o /dev/null
                                echo "Login tamamlandi."

                                echo "--- Security = low ---"
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    -X POST http://${DVWA_NAME}/security.php \\
                                    -d "seclev_submit=Submit&security=low" \\
                                    -L -o /dev/null
                                echo "Security level low ayarlandi."
                            '
                    """

                    echo "DVWA hazir ve yapilandirildi."
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // DAST Aşama 2: ZAP ile XSS taraması
        //
        // ZAP Automation Framework YAML'ı runtime'da oluşturulur çünkü
        // DVWA_NAME değişkeni build numarasına göre değişiyor.
        //
        // Tarama stratejisi:
        //   - Spider: DVWA sayfalarını keşfeder (authenticated)
        //   - Active Scan: SADECE XSS kuralları (40012, 40014, 40016, 40017)
        //     defaultStrength: disabled → listelenmeyenler devre dışı
        //     Sadece yukarıdaki 4 kural aktif, diğer 100+ kural çalışmaz
        //     → false positive oranı düşer, tarama hızlı biter
        //
        // Kimlik doğrulama:
        //   - ZAP, login.php'ye form POST yaparak kendi oturumunu açar
        //   - Önceki aşamada config'de default_security_level=low yapıldığı
        //     için ZAP'ın oturumu da "low" security ile başlar
        // ─────────────────────────────────────────────────────────────────────
        stage('DAST: ZAP XSS Scan') {
            steps {
                script {
                    def hostWorkspace = env.WORKSPACE.replace(
                        '/var/jenkins_home',
                        env.HOST_JENKINS_HOME
                    )

                    // ZAP Automation Framework YAML'ını workspace'e yaz
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
    # defaultStrength: disabled → listelenmemiş tüm kurallar devre dışı
    # Sadece aşağıdaki XSS kuralları çalışır, false positive azalır
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

                    // ZAP container'ını çalıştır
                    //   --network ${NET_NAME}  → DVWA'ya container adıyla ulaşabilir
                    //   -v hostWorkspace:/zap/wrk  → YAML'ı okur, raporu buraya yazar
                    //   || true  → ZAP bulgu bulursa exit 1 döner, pipeline durmasın
                    sh """
                        docker run --rm \\
                            --network ${NET_NAME} \\
                            -v ${hostWorkspace}:/zap/wrk/:rw \\
                            ghcr.io/zaproxy/zaproxy:stable \\
                            zap.sh -cmd -autorun /zap/wrk/zap-automation.yaml \\
                        || true
                    """

                    // Rapor dosyası kontrolü
                    // ZAP traditional-json template → reportFile + ".json" = zap-report.json
                    if (!fileExists('zap-report.json')) {
                        echo "UYARI: zap-report.json bulunamadi. Bos rapor olusturuluyor."
                        writeFile file: 'zap-report.json', text: '{"site":[]}'
                    }

                    def zapReport = new groovy.json.JsonSlurper().parseText(
                        readFile('zap-report.json')
                    )
                    def totalAlerts = zapReport.site?.collectMany { it.alerts ?: [] }?.size() ?: 0
                    echo "ZAP taramasi tamamlandi — toplam ${totalAlerts} alert."
                }
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // DAST Aşama 3: AI doğrulama ve GitHub Issue
        //
        // Bu aşama workflow'daki ai_analyze.py + create_issues.py mantığını
        // Jenkins pipeline'ına taşır.
        //
        // scripts/zap_analyze.py:
        //   1. zap-report.json'dan XSS bulgularını çeker
        //   2. Her bulgu için Groq LLM'e sorar: true/false positive?
        //   3. True positive çıkanları PoC'leriyle tek bir GitHub Issue'ya yazar
        //   4. zap-analysis.json'a tam sonuçları kaydeder
        //
        // Neden python:3.11-slim container?
        //   Jenkins container'ında requests kütüphanesi olmayabilir.
        //   Docker container ile temiz, tekrarlanabilir bir ortam sağlanır.
        //
        // Neden --network host?
        //   Python scripti Groq API ve GitHub API'ye internet üzerinden
        //   ulaşması gerekiyor. devsecops-net sadece dahili, internetsiz.
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
    // Post Actions — Her durumda çalışır (success, failure, abort)
    //
    // DVWA container ve network temizlenmezse host'ta birikirir!
    // "|| true" → zaten yoksa hata vermesin.
    // ─────────────────────────────────────────────────────────────────────────
    post {
        always {
            sh """
                echo "=== Temizlik ==="
                docker stop ${DVWA_NAME} 2>/dev/null || true
                docker rm   ${DVWA_NAME} 2>/dev/null || true
                docker network rm ${NET_NAME} 2>/dev/null || true
                echo "DVWA container ve network kaldirildi."
            """
            archiveArtifacts(
                artifacts: 'semgrep-report.json,zap-report.json,zap-automation.yaml,zap-analysis.json',
                allowEmptyArchive: true
            )
        }
    }
}
