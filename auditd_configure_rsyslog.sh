#/bin/bash
# Configuração do Rsyslog para Monitoramento de Eventos com AUDITD
# Versão 1.5
# Autor: [Carlos Silva](https://github.com/carlossilva9867)
# Envio de parametro exemplo ./scrit 1.1.1.1 
VARIAVEL_IP="$1"

# Função para verificar se o script está sendo executado como root ou com sudo
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] - Este script precisa ser executado com privilégios de root ou sudo."
        exit 1
    fi
}

# Função para verificar se o serviço do rsyslog está instalado
check_rsyslog() {
    if command -v rsyslogd >/dev/null 2>&1; then
        echo "[OK] - Serviço rsyslog já instalado no sistema operacional"
    else
        echo "[ERROR] - Serviço rsyslog não encontrado. Instale o rsyslog e execute o script novamente."
        echo "[INFO] - Para instalar o serviço, digite apt install rsyslog ou yum install rsyslog"
        exit 1
    fi
}

# Função para realizar backup dos arquivos de configuração do rsyslog
backup_rsyslog_conf() {
    local arquivo_config="/etc/rsyslog.conf"
    if [ -f "$arquivo_config" ]; then
        cp "$arquivo_config" "$arquivo_config.bak"
        echo "[OK] - Backup do arquivo de configuração do rsyslog realizado com sucesso"
    else
        echo "[ERROR] - Arquivo de configuração não encontrado: $arquivo_config. Não foi possível fazer o backup do rsyslog"
        exit 1
    fi
}

# Função para verificar os pré-requisitos
pre_requisitos(){
    check_root # chama a funcao check root
    check_rsyslog # chama a funcao check syslog 
}
# Funcao para instalar o auditd em debian e redhat 7/8
auditd_install() {
    local os_type=$(awk -F= '/^ID=/{print $2}' /etc/os-release)
    local os_version=$(awk -F= '/^VERSION_ID=/{print $2}' /etc/os-release)

    # Verificar se o auditd já está instalado
    if command -v auditd >/dev/null 2>&1; then
        echo "[OK] - auditd já está instalado. Nenhuma ação necessária."
        return
    fi

    case "$os_type" in
        "ubuntu" | "debian")
            echo "[INFO] - Sistema operacional detectado: Ubuntu/Debian"
            apt update
            apt install -y auditd
            ;;
        "centos" | "rhel")
            echo "[INFO] - Sistema operacional detectado: CentOS/RHEL"
            if [[ "$os_version" == *"7"* ]]; then
                yum install -y audit
            elif [[ "$os_version" == *"8"* ]]; then
                dnf install -y audit
            else
                echo "[ERROR] - Versão do CentOS/RHEL não suportada."
                exit 1
            fi
            ;;
        *)
            echo "[ERROR] - Sistema operacional não suportado ou não detectado."
            exit 1
            ;;
    esac

    echo "[OK] - Instalação do auditd concluída."
}

# Função com as configurações do rsyslog
rsyslog_configure() {
    echo "local6.* @@$VARIAVEL_IP" >> /etc/rsyslog.d/001-collector.conf
}

# Função para reiniciar o serviço
restart_rsyslog_service() {
    echo "[INFO] - Reiniciando o serviço rsyslog..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart rsyslog
    elif command -v service >/dev/null 2>&1; then
        service rsyslog restart
    else
        echo "[ERROR] - Não foi possível determinar o sistema de inicialização. Reinicie o serviço manualmente."
        exit 1
    fi

    # Aguardar um breve momento antes de verificar o status
    sleep 2

    # Verificar se o serviço está em execução
    if pgrep -x "rsyslogd" >/dev/null; then
        echo "[OK] - Serviço reiniciado com sucesso."
    else
        echo "[ERROR] - Falha ao reiniciar o serviço. Verifique os logs para mais detalhes."
        exit 1
    fi
}

# Função para adicionar as regras no auditd 
auditd_rules_add(){
    # Generic rule 
    curl -o /etc/audit/rules.d/soc.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules
}

# Função para adicionar um plugin de syslog no auditd
auditd_plugin_add(){
    # Testado apenas em ubuntu
    curl -o /etc/audit/plugins.d/collector.conf https://raw.githubusercontent.com/carlossilva9867/rsyslog-auditd/main/confs/audit/plguin-debian_syslog.conf
}

# Funcao para reiniciar e testar as configurações do auditd 
enable_auditd() {
  # Verificar o tipo de init system
  if command -v systemctl &> /dev/null && systemctl | grep -q '\-\.mount'; then
    # Se o comando 'systemctl' existe e contém '-.mount', é Systemd
    systemctl enable auditd
    systemctl restart auditd

    if systemctl is-active --quiet auditd; then
      echo "[OK] - O auditd foi habilitado e reiniciado com sucesso (Systemd)."
    else
      echo "[ERROR] - Houve um problema aobackup_rsyslog_conf iniciar o auditd. Verifique os logs para mais informações (Systemd)."
    fi
  elif command -v service &> /dev/null; then
    # Se o comando 'service' existe, é SystemV #{necessario validar}
    service auditd enable
    service auditd restart

    if service auditd status | grep -q "active (running)"; then
      echo "[OK] - O auditd foi habilitado e reiniciado com sucesso (SystemV)."
    else
      echo "[ERROR] - Houve um problema ao iniciar o auditd. Verifique os logs para mais informações (SystemV)."
    fi
  else
    echo "[ERROR] - Não foi possível determinar o tipo de init system."
  fi
}
# verificar se os serviços estão funcionando corretamente
check_services() {
    # Verificar o serviço Auditd (SystemD)
    if command -v systemctl &> /dev/null && systemctl is-active --quiet auditd && systemctl is-enabled --quiet auditd; then
        echo "[OK] - Serviço Auditd está em execução e configurado para iniciar na inicialização (SystemD)."
    elif command -v service &> /dev/null && service auditd status | grep -q "active (running)"; then
        echo "[OK] - Serviço Auditd está em execução (SystemV)."
    else
        echo "[ERROR] - Serviço Auditd não está em execução ou não está configurado corretamente."
        exit 1
    fi

    # Verificar o serviço Rsyslog (SystemD)
    if command -v systemctl &> /dev/null && systemctl is-active --quiet rsyslog && systemctl is-enabled --quiet rsyslog; then
        echo "[OK] - Serviço Rsyslog está em execução e configurado para iniciar na inicialização (SystemD)."
    elif command -v service &> /dev/null && service rsyslog status | grep -q "active (running)"; then
        echo "[OK] - Serviço Rsyslog está em execução (SystemV)."
    else
        echo "[ERROR] - Serviço Rsyslog não está em execução ou não está configurado corretamente."
        exit 1
    fi
}

# teste conexão
check_connection() {
 port="514" # porta do syslog
    # Testar conexão TCP OU UDP
    if (echo >/dev/tcp/"$VARIAVEL_IP"/"$port" || echo >/dev/udp/"$VARIAVEL_IP"/"$port") 2>/dev/null; then
        echo "[OK] - Conexão estabelecida com sucesso $VARIAVEL_IP porta $port"
    else
        echo "[ERROR] - Falha ao conectar $VARIAVEL_IP nas portas $port usando TCP e UDP"
        exit 1
    fi
}
# Função para validar a saude do serviço
health_check(){
check_services # valida se os serviços estão em execução
check_connection # valida se a comunicação é estabelecida com collector
}

# Função principal
main() {
    pre_requisitos # verificar os pre requisitos do sistema
    backup_rsyslog_conf # backup dos arquivos de configuração do rsyslog
    rsyslog_configure # configuração do rsyslog com arquivo do coletor
    auditd_install # instalar o auditd
    auditd_rules_add # realizar a configuração das regras
    auditd_plugin_add # habilita o facility 6 no syslog para os eventos de auditd
    enable_auditd # habilitando o auditd
    restart_rsyslog_service # restart do rsyslog
    health_check # 
    echo -e "\033[1;32m[OK] - Configurações realizadas com sucesso"
}
main