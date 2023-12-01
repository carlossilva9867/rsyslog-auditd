# Configuração do Rsyslog para Monitoramento de Eventos com AUDITD

  

## Visão Geral


Este script automatiza a configuração do Rsyslog para monitoramento de eventos do **AUDITD** em sistemas operacionais baseados em Linux. Ele é projetado para centralizar e enviar eventos de auditoria para um servidor remoto, proporcionando maior visibilidade e gerenciamento dos logs de auditoria.


----------

## Pré-requisitos

- O script deve ser executado com privilégios de root ou sudo.

- O serviço Rsyslog deve estar instalado no sistema operacional.

- O script foi testado e suporta os seguintes sistemas operacionais:
- [X] Ubuntu/Debian
- [?] CentOS/RHEL (7 e 8)

  

----------

  

## Uso
Execute o script fornecendo o endereço IP do servidor remoto como parâmetro. Exemplo:


    curl -o auditd_configure_rsyslog.sh https://raw.githubusercontent.com/carlossilva9867/rsyslog-auditd/main/auditd_configure_rsyslog.sh && chmod +x ./auditd_configure_rsyslog.sh && ./auditd_configure_rsyslog.sh "ip do coletor"

  

----------
## Funcionalidades Principais
1.  **Verificação de Privilégios de Execução**

- O script verifica se está sendo executado com privilégios de root ou sudo.

2.  **Verificação do Rsyslog**

- Verifica se o serviço Rsyslog está instalado no sistema operacional.

3.  **Backup do Arquivo de Configuração do Rsyslog**

- Realiza backup do arquivo de configuração do Rsyslog antes de fazer alterações.

4.  **Instalação do Auditd**

- Verifica e instala o Auditd, se ainda não estiver instalado.

5.  **Configuração do Rsyslog**

- Adiciona uma configuração específica para direcionar eventos de auditoria para o servidor remoto.

6.  **Adição de Regras no Auditd**

- Adiciona regras de auditoria usando um conju

7.  **Ativação do Auditd**

- Habilita e reinicia o serviço Auditd.

8.  **Reinicialização do Serviço Rsyslog**

- Reinicia o serviço Rsyslog para aplicar as configurações.

  

----------

  

## Execução do Script

  

Para executar o script, utilize o seguinte comando:

  
  

`./auditd_configure_rsyslog.sh <IP_do_Servidor_Remoto>`

 

----------
## Tabela de arquivos modificados
| Arquivo                                         | Descrição                                                                                                      |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `/etc/rsyslog.conf`                             | (O script realiza um backup deste arquivo antes de fazer alterações).|
| `/etc/rsyslog.d/001-collector.conf`             | **Arquivo de configuração criado** pelo script para configurar o Rsyslog com objetivo de direcionar todos os eventos de auditoria de saída para o executável `/sbin/audisp-syslog` usando a facilidade `LOG_LOCAL6` do syslog. |
| `/etc/audit/rules.d/soc.rules`                  | **Arquivo criado** contendo regras de auditoria do auditd. |

  ---

## Tabela de funções 
| Função                             | Descrição                                                                                                      |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `check_root`                       | Verifica se o script está sendo executado com privilégios de root ou sudo.                                     |
| `check_rsyslog`                    | Verifica se o serviço Rsyslog está instalado no sistema operacional.                                            |
| `backup_rsyslog_conf`              | Realiza backup do arquivo de configuração do Rsyslog antes de fazer alterações.                                  |
| `pre_requisitos`                   | Chama as funções `check_root` e `check_rsyslog` para verificar os pré-requisitos do sistema.                   |
| `auditd_install`                   | Instala o Auditd no sistema, se ainda não estiver instalado.                                                    |
| `rsyslog_configure`                | Adiciona uma configuração específica no Rsyslog para direcionar eventos de auditoria para um servidor remoto. |
| `restart_rsyslog_service`          | Reinicia o serviço Rsyslog para aplicar as configurações.                                                        |
| `auditd_rules_add`                 | Adiciona regras de auditoria no serviço auditd.                            |
| `enable_auditd`                    | Habilita e reinicia o serviço Auditd, verificando o tipo de sistema de inicialização (Systemd ou SystemV).      |
|`auditd_plugin_add` | Adiciona uma configuração de plugin no auditd para encaminhar os logs para o facility LOG_LOCAL6 do syslog
| `main`                             | Função principal que chama todas as funções necessárias para configurar o Rsyslog com o Auditd.                 |

Arquivo


- Certifique-se de revisar as configurações antes de executar o script em um ambiente de produção.