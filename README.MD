# Configuração do Rsyslog para Monitoramento de Eventos com AUDITD

## Visão Geral

Este script automatiza a configuração do Rsyslog para monitoramento de eventos com AUDITD em sistemas operacionais baseados em Linux. Ele é projetado para centralizar e enviar eventos de auditoria para um servidor remoto, proporcionando maior visibilidade e gerenciamento dos logs de auditoria.

----------

## Pré-requisitos

-   O script deve ser executado com privilégios de root ou sudo.
-   O serviço Rsyslog deve estar instalado no sistema operacional.
-   O script foi testado e suporta os seguintes sistemas operacionais:
    [X] Ubuntu/Debian
    [-]  CentOS/RHEL (7 e 8)

----------

## Uso

Execute o script fornecendo o endereço IP do servidor remoto como parâmetro. Exemplo:

`./auditd_configure_rsyslog 1.1.1.1` 

----------

## Funcionalidades Principais

1.  **Verificação de Privilégios de Execução**
    
    -   O script verifica se está sendo executado com privilégios de root ou sudo.
2.  **Verificação do Rsyslog**
    
    -   Verifica se o serviço Rsyslog está instalado no sistema operacional.
3.  **Backup do Arquivo de Configuração do Rsyslog**
    
    -   Realiza backup do arquivo de configuração do Rsyslog antes de fazer alterações.
4.  **Instalação do Auditd**
    
    -   Verifica e instala o Auditd, se ainda não estiver instalado.
5.  **Configuração do Rsyslog**
    
    -   Adiciona uma configuração específica para direcionar eventos de auditoria para o servidor remoto.
6.  **Adição de Regras no Auditd**
    
    -   Adiciona regras de auditoria usando um conju
7.  **Ativação do Auditd**
    
    -   Habilita e reinicia o serviço Auditd.
8.  **Reinicialização do Serviço Rsyslog**
    
    -   Reinicia o serviço Rsyslog para aplicar as configurações.

----------

## Execução do Script

Para executar o script, utilize o seguinte comando:


`./auditd_configure_rsyslog.sh <IP_do_Servidor_Remoto>` 

----------

## Notas
-   Certifique-se de revisar as configurações antes de executar o script em um ambiente de produção.