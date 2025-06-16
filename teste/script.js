// Elementos da interface
const logTextarea = document.getElementById('log');
const resultadoPre = document.getElementById('resultado');
const statusDiv = document.getElementById('status');
const logTypeSpan = document.getElementById('log-type');
const riskLevelSpan = document.getElementById('risk-level');
const modal = document.getElementById('modal');
const modalTitle = document.getElementById('modal-title');
const modalMessage = document.getElementById('modal-message');
const incidentCheckboxes = document.querySelectorAll('input[name="incidentType"]');
const templateSelector = document.getElementById('template');
const iocList = document.getElementById('ioc-list');

// Variáveis de estado
let currentSeverity = 'medium';

// Inicialização
document.addEventListener('DOMContentLoaded', () => {
    // Inicializar todas as categorias como expandidas
    document.querySelectorAll('.type-group').forEach(group => {
        group.classList.add('expanded');
    });
});

// Alternar visibilidade do grupo de categorias
function toggleCategoryGroup(element) {
    const group = element.parentElement;
    group.classList.toggle('collapsed');

    // Alternar ícone de seta
    const icon = element.querySelector('.fa-chevron-down, .fa-chevron-up');
    if (icon.classList.contains('fa-chevron-down')) {
        icon.classList.remove('fa-chevron-down');
        icon.classList.add('fa-chevron-up');
    } else {
        icon.classList.remove('fa-chevron-up');
        icon.classList.add('fa-chevron-down');
    }
}

// Adicionar campo IOC
function addIocField(iocValue = '') {
    const iocItem = document.createElement('div');
    iocItem.className = 'ioc-item';
    iocItem.innerHTML = `
        <input type="text" placeholder="IP, Hash, Domínio..." value="${iocValue}">
        <button onclick="this.parentElement.remove()"><i class="fas fa-times"></i></button>
    `;
    iocList.appendChild(iocItem);
}

// Obter IOCs inseridos
function getIocs() {
    const iocs = [];
    document.querySelectorAll('#ioc-list input').forEach(input => {
        if (input.value.trim()) {
            iocs.push(input.value.trim());
        }
    });
    return iocs;
}

// Obter saudação baseada no horário
function getSaudacao() {
    const hora = new Date().getHours();
    if (hora < 12) return "bom dia";
    if (hora < 18) return "boa tarde";
    return "boa noite";
}

// Alternar checkbox
function toggleCheckbox(id) {
    const checkbox = document.getElementById(id);
    checkbox.checked = !checkbox.checked;
    checkbox.dispatchEvent(new Event('change'));
}

// Mostrar modal
function mostrarModal(titulo, mensagem) {
    modalTitle.textContent = titulo;
    modalMessage.textContent = mensagem;
    modal.classList.add('active');
}

// Fechar modal
function fecharModal() {
    modal.classList.remove('active');
}

// Limpar entrada
function limparEntrada() {
    logTextarea.value = '';
    resultadoPre.textContent = '[Seu relatório de segurança aparecerá aqui]';
    statusDiv.innerHTML = '<i class="fas fa-clock"></i> AGUARDANDO ENTRADA...';
    statusDiv.className = 'status status-waiting';
    logTypeSpan.classList.add('hidden');
    riskLevelSpan.classList.add('hidden');

    // Limpar checkboxes
    incidentCheckboxes.forEach(cb => cb.checked = false);

    // Limpar IOCs
    iocList.innerHTML = '';
}

// Obter tipos de incidente selecionados
function getSelectedIncidentTypes() {
    const selected = [];
    incidentCheckboxes.forEach(cb => {
        if (cb.checked) selected.push(cb.value);
    });
    return selected;
}

// Extrair dados automaticamente do log
function extrairDados() {
    const log = logTextarea.value;
    if (!log.trim()) {
        mostrarModal('ENTRADA VAZIA', 'Por favor, cole um log para extrair dados.');
        return;
    }

    // Extrair dados com expressões regulares mais precisas
    const dadosExtraidos = {
        data: extrairData(log),
        ipOrigem: extrairIpOrigem(log),
        usuario: extrairUsuario(log),
        acao: extrairAcao(log),
        mensagem: extrairMensagem(log) || extrairMensagemAlternativa(log),
        hostOrigem: extrairHostOrigem(log),
        hostDestino: extrairHostDestino(log),
        processo: extrairProcesso(log),
        regra: extrairRegra(log),
        grupo: extrairGrupo(log),
        objeto: extrairObjeto(log),
        nomeObjeto: extrairNomeObjeto(log),
        tipoObjeto: extrairTipoObjeto(log),
        assunto: extrairAssunto(log),
        politica: extrairPolitica(log),
        idFornecedor: extrairIdFornecedor(log),
        navegador: extrairNavegador(log),
        iocs: extrairIocs(log)
    };

    // Preencher IOCs encontrados
    iocList.innerHTML = '';
    dadosExtraidos.iocs.forEach(ioc => addIocField(ioc));

    // Tentar detectar tipo de incidente automaticamente
    const incidentType = detectarTipoLog(log);
    if (incidentType) {
        document.querySelectorAll('input[name="incidentType"]').forEach(cb => {
            cb.checked = cb.value === incidentType;
        });
        logTypeSpan.textContent = incidentType.toUpperCase();
        logTypeSpan.classList.remove('hidden');
    }

    mostrarModal('DADOS EXTRAÍDOS', `
Foram identificados os seguintes dados no log:
        
Data: ${dadosExtraidos.data || 'Não encontrada'}
IP de Origem: ${dadosExtraidos.ipOrigem || 'Não encontrado'}
Host de Origem: ${dadosExtraidos.hostOrigem || 'Não encontrado'}
Host de Destino: ${dadosExtraidos.hostDestino || 'Não encontrado'}
Usuário: ${dadosExtraidos.usuario || 'Não encontrado'}
Ação: ${dadosExtraidos.acao || 'Não encontrada'}
Processo: ${dadosExtraidos.processo || 'Não encontrado'}
Regra: ${dadosExtraidos.regra || 'Não encontrada'}
Mensagem: ${dadosExtraidos.mensagem || 'Não disponível'}
    `);
}

// Funções de extração melhoradas
function extrairData(texto) {
    const padrao1 = /(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/; // YYYY-MM-DD HH:MM:SS
    const padrao2 = /(\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2})/; // DD/MM/YYYY HH:MM:SS
    const padrao3 = /(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2} \d{2}:\d{2}:\d{2}/; // MMM DD HH:MM:SS

    const match = texto.match(padrao1) || texto.match(padrao2) || texto.match(padrao3);
    return match ? match[0] : null;
}

function extrairIpOrigem(texto) {
    const padrao = /(?:from|source|src|origin)[:=]?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairUsuario(texto) {
    const padrao = /(?:user|username|login|account)[:=]?\s*['"]?(\w+)['"]?/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairAcao(texto) {
    const padrao = /(block|deny|allow|permit|alert|detect|drop|accept)/i;
    const match = texto.match(padrao);
    return match ? match[0] : null;
}

function extrairMensagem(texto) {
    const padrao = /(?:message|msg|description)[:=]?\s*['"](.*?)['"]/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairMensagemAlternativa(texto) {
    const padrao = /(?:description|details|info)\s*[:=]\s*['"]?(.*?)['"]?[\s;]/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairHostOrigem(texto) {
    const padrao = /(?:source host|src host|origin host)\s*[:=]\s*['"]?([\w\-\.]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairHostDestino(texto) {
    const padrao = /(?:destination host|dest host|target host)\s*[:=]\s*['"]?([\w\-\.]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairProcesso(texto) {
    const padrao = /(?:process|process name|image)\s*[:=]\s*['"]?([\w\-\.]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairRegra(texto) {
    const padrao = /(?:rule|policy|signature)\s*[:=]\s*['"]?([\w\-\.\s]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairGrupo(texto) {
    const padrao = /(?:group|user group)\s*[:=]\s*['"]?([\w\-\.]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairObjeto(texto) {
    const padrao = /(?:object|target)\s*[:=]\s*['"]?([\w\-\.]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairNomeObjeto(texto) {
    const padrao = /(?:object name|target name)\s*[:=]\s*['"]?([\w\-\.\s]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairTipoObjeto(texto) {
    const padrao = /(?:object type|target type)\s*[:=]\s*['"]?([\w\-\.]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairAssunto(texto) {
    const padrao = /(?:subject|title)\s*[:=]\s*['"]?([\w\-\.\s]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairPolitica(texto) {
    const padrao = /(?:policy|security policy)\s*[:=]\s*['"]?([\w\-\.\s]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairIdFornecedor(texto) {
    const padrao = /(?:vendor id|provider id)\s*[:=]\s*['"]?([\w\-\.]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairNavegador(texto) {
    const padrao = /(?:browser|user agent)\s*[:=]\s*['"]?([\w\-\.\s]+)/i;
    const match = texto.match(padrao);
    return match ? match[1] : null;
}

function extrairIocs(texto) {
    const ips = texto.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g) || [];
    const hashes = texto.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) || [];
    const domains = texto.match(/\b[a-z0-9-]+\.(com|net|org|gov|br|local)\b/gi) || [];

    return [...new Set([...ips, ...hashes, ...domains])]; // Remove duplicates
}

// Detectar tipo de log automaticamente com mais precisão
function detectarTipoLog(log) {
    const patterns = {
        "Conexão Inbound Suspeita": /(inbound connection|suspicious connection|unexpected connection)/i,
        "Acesso a IPs suspeitos": /(access to malicious IP|connection to suspicious IP)/i,
        "Falhas de autenticação": /(failed login|authentication failure|invalid credentials)/i,
        "Silent Log Source": /(log source stopped|no logs received|silent log)/i,
        "Heartbeat": /(heartbeat lost|missing heartbeat)/i,
        "Host Critical Condition": /(host critical|system critical condition)/i,
        "Malware": /(malware|virus|trojan|ransomware)/i,
        "Vulnerabilidades Encontradas": /(vulnerability|cve-\d{4}-\d+|exploit)/i,
        "Usuário ADD Grupo": /(user added to group|group membership changed)/i,
        "Midia Removivel": /(usb device|removable media|external storage)/i,
        "Exfiltração": /(data exfiltration|unauthorized data transfer)/i,
        "Senha Administrador Alterada": /(admin password changed|administrator credential change)/i,
        "Usuário ADD Grupo de ADMIN": /(user added to admin group|administrative privileges granted)/i,
        "CyberArk": /(cyberark|privileged access management)/i,
        "Comunicação Inbound TOR": /(tor connection|onion router)/i,
        "Alteração de senha por usuário administrator": /(administrator password change)/i,
        "Canary List (comunicação maliciosa)": /(canary list|malicious communication)/i
    };

    for (const [tipo, regex] of Object.entries(patterns)) {
        if (regex.test(log)) return tipo;
    }

    return null;
}

// Gerar link de IOC com mais serviços
function gerarLinksIOC(ioc) {
    if (!ioc) return "N/A";

    const links = [];

    if (ioc.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
        links.push(`https://www.abuseipdb.com/check/${ioc}`);
        links.push(`https://www.virustotal.com/gui/ip-address/${ioc}`);
        links.push(`https://talosintelligence.com/reputation_center/lookup?search=${ioc}`);
    } else if (ioc.match(/^[a-f0-9]{32}$/i) || ioc.match(/^[a-f0-9]{40}$/i) || ioc.match(/^[a-f0-9]{64}$/i)) {
        links.push(`https://www.virustotal.com/gui/file/${ioc}`);
        links.push(`https://www.hybrid-analysis.com/search?query=${ioc}`);
    } else if (ioc.match(/^[a-z0-9-]+\.[a-z]{2,}/i)) {
        links.push(`https://www.virustotal.com/gui/domain/${ioc}`);
        links.push(`https://urlscan.io/search/#${ioc}`);
    }

    return links.length > 0 ? links.join(", ") : "N/A";
}

// Função auxiliar para adicionar campos apenas se existirem
function adicionarCampoSeExistir(rotulo, valor) {
    return valor ? `${rotulo}: ${valor}` : '';
}

// Gerar relatório completo
async function gerarRelatorio() {
    const log = logTextarea.value.trim();

    if (!log) {
        mostrarModal('ENTRADA VAZIA', 'Por favor, cole um log de segurança para análise.');
        return;
    }

    const selectedTypes = getSelectedIncidentTypes();
    if (selectedTypes.length === 0) {
        mostrarModal('SEM CATEGORIA', 'Por favor, selecione pelo menos uma categoria de incidente.');
        return;
    }

    const tipoLog = selectedTypes.join(' + ');
    const fonteLog = templateSelector.value === 'padrao' ? 'Sistema de Monitoramento' : templateSelector.options[templateSelector.selectedIndex].text;
    const iocs = getIocs();

    // Atualizar UI para estado de processamento
    statusDiv.innerHTML = '<div class="loading"></div> GERANDO RELATÓRIO...';
    statusDiv.className = 'status status-processing';
    resultadoPre.textContent = '';
    logTypeSpan.textContent = tipoLog.toUpperCase();
    logTypeSpan.classList.remove('hidden');
    riskLevelSpan.classList.remove('hidden');

    try {
        // Extrair dados do log com maior precisão
        const dados = {
            data: extrairData(log),
            ipOrigem: extrairIpOrigem(log),
            usuario: extrairUsuario(log),
            acao: extrairAcao(log),
            mensagem: extrairMensagem(log) || extrairMensagemAlternativa(log),
            hostOrigem: extrairHostOrigem(log),
            hostDestino: extrairHostDestino(log),
            processo: extrairProcesso(log),
            regra: extrairRegra(log),
            grupo: extrairGrupo(log),
            objeto: extrairObjeto(log),
            nomeObjeto: extrairNomeObjeto(log),
            tipoObjeto: extrairTipoObjeto(log),
            assunto: extrairAssunto(log),
            politica: extrairPolitica(log),
            idFornecedor: extrairIdFornecedor(log),
            navegador: extrairNavegador(log)
        };

        // Preencher automaticamente os IOCs nos campos relevantes
        if (iocs.length > 0 && !dados.ipOrigem) {
            dados.ipOrigem = iocs[0];
        }

        // Gerar relatório completo
        let relatorio = `
Prezados(as), ${getSaudacao()}.

Nossa equipe identificou uma atividade suspeita em seu ambiente. Seguem abaixo mais detalhes para validação:

Caso de uso: ${tipoLog}

🕵 Análise:
Objetivo do caso de uso: ${getDescricaoCasoUso(tipoLog)}

Fonte de dados utilizada na análise: ${fonteLog}

🧾 Evidências:`;

        // Adicionar apenas campos preenchidos
        relatorio += adicionarCampoSeExistir("\nData do Log", dados.data);
        relatorio += adicionarCampoSeExistir("\nFonte do Log", fonteLog);
        relatorio += adicionarCampoSeExistir("\nUsuário de Origem", dados.usuario);
        relatorio += adicionarCampoSeExistir("\nUsuário Afetado", dados.usuario);

        if (dados.ipOrigem) {
            let ipHostOrigem = dados.ipOrigem;
            if (dados.hostOrigem) ipHostOrigem += ` (${dados.hostOrigem})`;
            relatorio += `\nIP/Host de Origem: ${ipHostOrigem}`;
        }

        if (dados.ipOrigem) {
            let ipHostDestino = dados.ipOrigem;
            if (dados.hostDestino) ipHostDestino += ` (${dados.hostDestino})`;
            relatorio += `\nIP/Host Afetado: ${ipHostDestino}`;
        }

        relatorio += adicionarCampoSeExistir("\nLocalização (Origem/Impactado)", "Não identificada");
        relatorio += `\nTipo do Evento: ${tipoLog}`;
        relatorio += adicionarCampoSeExistir("\nGrupo", dados.grupo);
        relatorio += adicionarCampoSeExistir("\nObjeto", dados.objeto);
        relatorio += adicionarCampoSeExistir("\nNome do Objeto", dados.nomeObjeto);
        relatorio += adicionarCampoSeExistir("\nTipo do Objeto", dados.tipoObjeto);
        relatorio += adicionarCampoSeExistir("\nAssunto", dados.assunto);
        relatorio += adicionarCampoSeExistir("\nPolítica", dados.politica);
        relatorio += `\nNome da Ameaça: ${tipoLog}`;
        relatorio += adicionarCampoSeExistir("\nNome do Processo", dados.processo);
        relatorio += adicionarCampoSeExistir("\nNome da Regra MPE", dados.regra);
        relatorio += adicionarCampoSeExistir("\nMensagem do Fornecedor", dados.mensagem);
        relatorio += adicionarCampoSeExistir("\nID do Fornecedor", dados.idFornecedor);
        relatorio += adicionarCampoSeExistir("\nIdentificador de Navegador", dados.navegador);
        relatorio += adicionarCampoSeExistir("\nAção", dados.acao);

        if (dados.acao) {
            const status = (dados.acao === 'block' || dados.acao === 'deny') ? 'Bloqueado' : 'Permitido';
            relatorio += `\nStatus: ${status}`;
            relatorio += `\nResultado: ${status === 'Bloqueado' ? 'Acesso negado' : 'Acesso permitido'}`;
        }

        relatorio += adicionarCampoSeExistir("\nMensagem de Log", dados.mensagem);

        if (iocs.length > 0) {
            relatorio += `\nIOC: ${iocs.map(ioc => gerarLinksIOC(ioc)).join('\n')}`;
        }

        relatorio += `\n\n🕵 Justificativa para abertura do caso: ${getJustificativaEnriquecida(tipoLog, dados, iocs)}`;
        relatorio += `\n\n✅ Ações tomadas:\n${getAcaoTomadaDetalhada(tipoLog, dados, iocs)}`;
        relatorio += `\n\n📌 Recomendações:\n${getRecomendacoesAprimoradas(tipoLog, dados, iocs)}`;

        // Mostrar resultado
        resultadoPre.textContent = relatorio;

        statusDiv.innerHTML = '<i class="fas fa-check-circle"></i> RELATÓRIO GERADO!';
        statusDiv.className = 'status status-success';

    } catch (error) {
        console.error('Erro detalhado:', error);
        resultadoPre.textContent = 'Ocorreu um erro durante a geração do relatório.';
        statusDiv.innerHTML = '<i class="fas fa-exclamation-circle"></i> ERRO NO PROCESSAMENTO';
        statusDiv.className = 'status status-error';
        mostrarModal('ERRO CRÍTICO', `Ocorreu um erro durante o processamento: ${error.message}`);
    }
}

// Função de justificativa enriquecida baseada no modelo Python
function getJustificativaEnriquecida(tipo, dados, iocs) {
    let justificativa = `A atividade foi classificada como suspeita devido aos seguintes fatores:\n\n`;

    // Classificação de risco baseada na severidade selecionada
    const classificacaoRisco = {
        'low': 'BAIXO',
        'medium': 'MÉDIO',
        'high': 'ALTO',
        'critical': 'CRÍTICO'
    };

    justificativa += `• Classificação de Risco: ${classificacaoRisco[currentSeverity]}\n`;

    // Contexto específico baseado no tipo de incidente
    switch (tipo) {
        case "Acesso a IPs suspeitos":
            justificativa += `• Comunicação estabelecida com endereços conhecidamente maliciosos (${iocs.join(', ')})\n`;
            justificativa += `• Padrão consistente com conexões a redes de comando e controle (C2)\n`;
            justificativa += `• Risco de comprometimento persistente ou exfiltração de dados\n`;
            break;

        case "Falhas de autenticação":
            justificativa += `• Múltiplas tentativas de autenticação falha para a conta ${dados.usuario}\n`;
            justificativa += `• Padrão consistente com ataque de força bruta ou dicionário\n`;
            justificativa += `• Risco de comprometimento de credenciais\n`;
            break;

        case "Malware":
            justificativa += `• Atividade consistente com presença de malware no sistema\n`;
            justificativa += `• Risco significativo à confidencialidade e integridade dos dados\n`;
            justificativa += `• Potencial vetor para outros ataques na rede\n`;
            break;

        case "Exfiltração":
            justificativa += `• Padrões de transferência de dados consistentes com exfiltração\n`;
            justificativa += `• Possível comprometimento avançado ou insider threat\n`;
            justificativa += `• Risco de vazamento de dados sensíveis\n`;
            break;

        case "Usuário ADD Grupo de ADMIN":
            justificativa += `• Adição não autorizada de usuário a grupo administrativo\n`;
            justificativa += `• Possível tentativa de escalonamento de privilégios\n`;
            justificativa += `• Risco de acesso não autorizado a sistemas críticos\n`;
            break;

        default:
            justificativa += `• Atividade anômala detectada no ambiente\n`;
            justificativa += `• Padrão consistente com atividades maliciosas conhecidas\n`;
    }

    // Contexto técnico adicional
    justificativa += `\nContexto técnico adicional:\n`;
    if (dados.ipOrigem) {
        justificativa += `• Origem: ${dados.ipOrigem} ${dados.hostOrigem ? '(' + dados.hostOrigem + ')' : ''}\n`;
    }
    if (dados.acao) {
        justificativa += `• Ação detectada: ${dados.acao}\n`;
    }
    if (dados.processo) {
        justificativa += `• Processo envolvido: ${dados.processo}\n`;
    }
    if (dados.regra) {
        justificativa += `• Regra acionada: ${dados.regra}\n`;
    }

    // Referência a frameworks de segurança
    justificativa += `\nReferência a frameworks de segurança:\n`;
    justificativa += `• MITRE ATT&CK: ${getTecnicasMitre(tipo)}\n`;
    justificativa += `• NIST CSF: ${getNistCsf(tipo)}\n`;

    return justificativa;
}

// Função de ações tomadas detalhadas
function getAcaoTomadaDetalhada(tipo, dados, iocs) {
    let acoes = `• Análise inicial realizada e documentada\n`;

    switch (tipo) {
        case "Acesso a IPs suspeitos":
            acoes += `• Bloqueio imediato dos IPs maliciosos (${iocs.join(', ')}) no firewall perimetral\n`;
            acoes += `• Isolamento preventivo dos sistemas envolvidos\n`;
            acoes += `• Coleta de evidências forenses para análise posterior\n`;
            acoes += `• Notificação imediata às equipes de segurança e operações\n`;
            break;

        case "Falhas de autenticação":
            acoes += `• Bloqueio temporário da conta ${dados.usuario}\n`;
            acoes += `• Implementação de monitoramento adicional para a conta\n`;
            acoes += `• Verificação de contas com senhas fracas no sistema\n`;
            acoes += `• Notificação ao proprietário da conta sobre a atividade suspeita\n`;
            break;

        case "Malware":
            acoes += `• Isolamento imediato do sistema afetado da rede\n`;
            acoes += `• Varredura completa do sistema com ferramentas atualizadas\n`;
            acoes += `• Coleta de amostras para análise forense\n`;
            acoes += `• Notificação às equipes de segurança e TI\n`;
            break;

        case "Exfiltração":
            acoes += `• Bloqueio das conexões suspeitas identificadas\n`;
            acoes += `• Auditoria dos dados potencialmente exfiltrados\n`;
            acoes += `• Revisão dos controles de acesso aos dados sensíveis\n`;
            acoes += `• Notificação ao comitê de segurança da informação\n`;
            break;

        case "Usuário ADD Grupo de ADMIN":
            acoes += `• Remoção imediata do usuário do grupo administrativo\n`;
            acoes += `• Reset das credenciais do usuário envolvido\n`;
            acoes += `• Auditoria das permissões de todos os usuários administrativos\n`;
            acoes += `• Notificação ao departamento de segurança da informação\n`;
            break;

        default:
            acoes += `• Implementação de monitoramento adicional para atividades similares\n`;
    }

    acoes += `• Atualização dos sistemas de detecção com os IOCs identificados\n`;
    return acoes;
}

// Função de recomendações aprimoradas
function getRecomendacoesAprimoradas(tipo, dados, iocs) {
    let recomendacoes = `1. Contenção imediata:\n`;

    switch (tipo) {
        case "Acesso a IPs suspeitos":
            recomendacoes += `   • Manter o bloqueio dos IPs maliciosos (${iocs.join(', ')})\n`;
            recomendacoes += `   • Verificar sistemas que estabeleceram comunicação com esses endereços\n`;
            recomendacoes += `   • Isolar sistemas potencialmente comprometidos\n\n`;

            recomendacoes += `2. Investigação detalhada:\n`;
            recomendacoes += `   • Analisar logs completos dos sistemas envolvidos\n`;
            recomendacoes += `   • Verificar existência de conexões persistentes\n`;
            recomendacoes += `   • Buscar por indicadores adicionais de comprometimento\n\n`;

            recomendacoes += `3. Medidas corretivas:\n`;
            recomendacoes += `   • Atualizar regras de firewall para bloquear categorias de IPs maliciosos\n`;
            recomendacoes += `   • Implementar solução de Threat Intelligence para atualização automática de listas de bloqueio\n`;
            recomendacoes += `   • Revisar políticas de saída na rede corporativa\n\n`;

            recomendacoes += `4. Prevenção futura:\n`;
            recomendacoes += `   • Implementar monitoramento contínuo de comunicações externas\n`;
            recomendacoes += `   • Atualizar treinamento de conscientização sobre ameaças externas\n`;
            recomendacoes += `   • Realizar teste de penetração para identificar vetores similares\n`;
            break;

        case "Falhas de autenticação":
            recomendacoes += `   • Implementar autenticação multifator para contas privilegiadas\n`;
            recomendacoes += `   • Configurar bloqueio temporário após múltiplas tentativas falhas\n\n`;

            recomendacoes += `2. Investigação detalhada:\n`;
            recomendacoes += `   • Verificar se a conta foi comprometida\n`;
            recomendacoes += `   • Analisar logs de acesso para identificar padrões de ataque\n\n`;

            recomendacoes += `3. Medidas corretivas:\n`;
            recomendacoes += `   • Resetar senha da conta ${dados.usuario}\n`;
            recomendacoes += `   • Educar usuários sobre criação de senhas seguras\n\n`;

            recomendacoes += `4. Prevenção futura:\n`;
            recomendacoes += `   • Implementar solução de gerenciamento de identidade e acesso\n`;
            recomendacoes += `   • Monitorar tentativas de login suspeitas\n`;
            break;

        case "Malware":
            recomendacoes += `   • Manter o sistema isolado até conclusão da análise\n`;
            recomendacoes += `   • Verificar outros sistemas na mesma rede\n\n`;

            recomendacoes += `2. Investigação detalhada:\n`;
            recomendacoes += `   • Identificar vetor de infecção inicial\n`;
            recomendacoes += `   • Determinar escopo total do comprometimento\n\n`;

            recomendacoes += `3. Medidas corretivas:\n`;
            recomendacoes += `   • Realizar limpeza completa do sistema ou reinstalação\n`;
            recomendacoes += `   • Atualizar todas as assinaturas de antivírus\n\n`;

            recomendacoes += `4. Prevenção futura:\n`;
            recomendacoes += `   • Implementar solução EDR para detecção avançada\n`;
            recomendacoes += `   • Treinar usuários em identificação de phishing\n`;
            break;

        case "Exfiltração":
            recomendacoes += `   • Bloquear todos os canais de exfiltração identificados\n`;
            recomendacoes += `   • Isolar sistemas que podem ter sido comprometidos\n\n`;

            recomendacoes += `2. Investigação detalhada:\n`;
            recomendacoes += `   • Determinar quais dados foram exfiltrados\n`;
            recomendacoes += `   • Identificar ponto inicial do comprometimento\n\n`;

            recomendacoes += `3. Medidas corretivas:\n`;
            recomendacoes += `   • Implementar soluções DLP (Data Loss Prevention)\n`;
            recomendacoes += `   • Revisar controles de acesso a dados sensíveis\n\n`;

            recomendacoes += `4. Prevenção futura:\n`;
            recomendacoes += `   • Monitorar padrões anômalos de transferência de dados\n`;
            recomendacoes += `   • Implementar criptografia para dados sensíveis\n`;
            break;

        case "Usuário ADD Grupo de ADMIN":
            recomendacoes += `   • Reverter todas as alterações não autorizadas de permissões\n`;
            recomendacoes += `   • Resetar credenciais do usuário envolvido\n\n`;

            recomendacoes += `2. Investigação detalhada:\n`;
            recomendacoes += `   • Determinar como a alteração foi realizada\n`;
            recomendacoes += `   • Verificar se houve comprometimento da conta\n\n`;

            recomendacoes += `3. Medidas corretivas:\n`;
            recomendacoes += `   • Implementar aprovação em duas etapas para alterações em grupos administrativos\n`;
            recomendacoes += `   • Auditar todas as contas com privilégios elevados\n\n`;

            recomendacoes += `4. Prevenção futura:\n`;
            recomendacoes += `   • Implementar solução PAM (Privileged Access Management)\n`;
            recomendacoes += `   • Configurar alertas para alterações em grupos administrativos\n`;
            break;

        default:
            recomendacoes += `1. Documentar incidente detalhadamente\n`;
            recomendacoes += `2. Notificar equipe de segurança para análise complementar\n`;
            recomendacoes += `3. Monitorar atividades similares em outros sistemas\n`;
            recomendacoes += `4. Revisar controles de segurança relevantes\n`;
    }

    return recomendacoes;
}

// Funções auxiliares adicionais
function getTecnicasMitre(tipo) {
    // Mapear tipos de incidente para técnicas MITRE ATT&CK
    const tecnicas = {
        "Acesso a IPs suspeitos": "T1071 - Application Layer Protocol, T1043 - Commonly Used Port",
        "Falhas de autenticação": "T1110 - Brute Force, T1078 - Valid Accounts",
        "Malware": "T1204 - User Execution, T1059 - Command-Line Interface",
        "Exfiltração": "T1041 - Exfiltration Over C2 Channel, T1020 - Automated Exfiltration",
        "Usuário ADD Grupo de ADMIN": "T1098 - Account Manipulation, T1078 - Valid Accounts",
        "Conexão Inbound Suspeita": "T1190 - Exploit Public-Facing Application",
        "Silent Log Source": "T1070 - Indicator Removal on Host",
        "Heartbeat": "T1070 - Indicator Removal on Host",
        "Host Critical Condition": "T1499 - Endpoint Denial of Service",
        "Vulnerabilidades Encontradas": "T1190 - Exploit Public-Facing Application",
        "Usuário ADD Grupo": "T1098 - Account Manipulation",
        "Midia Removivel": "T1091 - Replication Through Removable Media",
        "Senha Administrador Alterada": "T1098 - Account Manipulation",
        "CyberArk": "T1078 - Valid Accounts",
        "Comunicação Inbound TOR": "T1071 - Application Layer Protocol",
        "Alteração de senha por usuário administrator": "T1098 - Account Manipulation",
        "Canary List (comunicação maliciosa)": "T1071 - Application Layer Protocol"
    };

    return tecnicas[tipo] || "Técnicas serão determinadas após análise mais aprofundada";
}

function getNistCsf(tipo) {
    // Mapear tipos de incidente para categorias NIST CSF
    const categorias = {
        "Acesso a IPs suspeitos": "DE.CM-4 - Malicious code is detected, PR.IP-1 - Baseline configuration is maintained",
        "Falhas de autenticação": "PR.AC-1 - Identities and credentials are managed, PR.AC-7 - Users, devices, and other assets are authenticated",
        "Malware": "PR.IP-1 - Baseline configuration is maintained, DE.CM-4 - Malicious code is detected",
        "Exfiltração": "PR.DS-5 - Protections against data leaks are implemented, DE.CM-7 - Monitoring for unauthorized personnel",
        "Usuário ADD Grupo de ADMIN": "PR.AC-1 - Identities and credentials are managed, PR.AC-4 - Access permissions are managed",
        "Conexão Inbound Suspeita": "PR.IP-1 - Baseline configuration is maintained, DE.CM-1 - The network is monitored",
        "Silent Log Source": "DE.CM-3 - Event detection information is communicated",
        "Heartbeat": "DE.CM-3 - Event detection information is communicated",
        "Host Critical Condition": "PR.IP-1 - Baseline configuration is maintained, RS.AN-1 - Notifications from detection systems are investigated",
        "Vulnerabilidades Encontradas": "PR.IP-1 - Baseline configuration is maintained, PR.IP-12 - Vulnerability plan is developed",
        "Usuário ADD Grupo": "PR.AC-1 - Identities and credentials are managed, PR.AC-4 - Access permissions are managed",
        "Midia Removivel": "PR.AC-3 - Remote access is managed, PR.DS-5 - Protections against data leaks are implemented",
        "Senha Administrador Alterada": "PR.AC-1 - Identities and credentials are managed, PR.AC-4 - Access permissions are managed",
        "CyberArk": "PR.AC-1 - Identities and credentials are managed, PR.AC-4 - Access permissions are managed",
        "Comunicação Inbound TOR": "PR.IP-1 - Baseline configuration is maintained, DE.CM-1 - The network is monitored",
        "Alteração de senha por usuário administrator": "PR.AC-1 - Identities and credentials are managed, PR.AC-4 - Access permissions are managed",
        "Canary List (comunicação maliciosa)": "PR.IP-1 - Baseline configuration is maintained, DE.CM-1 - The network is monitored"
    };

    return categorias[tipo] || "Categorias serão determinadas após análise mais aprofundada";
}

// Obter descrição do caso de uso melhorada
function getDescricaoCasoUso(tipo) {
    const descricoes = {
        "Conexão Inbound Suspeita": "Detectar conexões suspeitas de entrada no ambiente que podem indicar tentativas de invasão ou exploração de vulnerabilidades.",
        "Acesso a IPs suspeitos": "Identificar comunicações com endereços IPs conhecidamente maliciosos ou pertencentes a redes de comando e controle.",
        "Falhas de autenticação": "Monitorar múltiplas tentativas de login malsucedidas que podem indicar tentativas de força bruta ou ataques de dicionário.",
        "Silent Log Source": "Identificar fontes de log que pararam de enviar eventos, o que pode indicar problemas técnicos ou tentativas de ocultar atividades maliciosas.",
        "Heartbeat": "Monitorar sinais de vida de sistemas e serviços para detectar falhas ou indisponibilidades.",
        "Host Critical Condition": "Identificar sistemas em estado crítico que podem afetar a segurança ou disponibilidade dos serviços.",
        "Malware": "Detectar a presença de software malicioso no ambiente que pode comprometer a confidencialidade, integridade ou disponibilidade dos dados.",
        "Vulnerabilidades Encontradas": "Identificar sistemas com vulnerabilidades conhecidas que podem ser exploradas por atacantes.",
        "Usuário ADD Grupo": "Monitorar alterações não autorizadas em grupos de usuários que podem indicar tentativas de escalonamento de privilégios.",
        "Midia Removivel": "Detectar a conexão de dispositivos de armazenamento removíveis que podem ser usados para exfiltrar dados ou introduzir malware.",
        "Exfiltração": "Identificar transferências não autorizadas de dados sensíveis para fora do ambiente controlado.",
        "Senha Administrador Alterada": "Monitorar alterações não autorizadas em credenciais privilegiadas que podem indicar comprometimento de contas.",
        "Usuário ADD Grupo de ADMIN": "Detectar adições não autorizadas de usuários a grupos administrativos que podem indicar tentativas de escalonamento de privilégios.",
        "CyberArk": "Monitorar atividades relacionadas ao gerenciamento de credenciais privilegiadas no CyberArk.",
        "Comunicação Inbound TOR": "Identificar comunicações suspeitas originadas da rede TOR que podem indicar tentativas de acesso anônimo malicioso.",
        "Alteração de senha por usuário administrator": "Monitorar alterações não autorizadas em credenciais administrativas.",
        "Canary List (comunicação maliciosa)": "Detectar comunicações com endereços conhecidamente maliciosos ou em listas de bloqueio."
    };

    return descricoes[tipo] || "Atividade suspeita identificada no ambiente, requerendo análise e ação apropriadas.";
}

// Copiar relatório
function copiarRelatorio() {
    const texto = resultadoPre.textContent;

    if (texto.includes('[Seu relatório')) {
        mostrarModal('AVISO', 'Gere um relatório antes de copiar.');
        return;
    }

    navigator.clipboard.writeText(texto)
        .then(() => mostrarModal('SUCESSO', 'Relatório copiado para a área de transferência!'))
        .catch(err => {
            console.error('Erro ao copiar:', err);
            mostrarModal('ERRO', 'Falha ao copiar relatório. Consulte o console.');
        });
}

// Exportar relatório
function exportarRelatorio() {
    const texto = resultadoPre.textContent;

    if (texto.includes('[Seu relatório')) {
        mostrarModal('AVISO', 'Gere um relatório antes de exportar.');
        return;
    }

    const blob = new Blob([texto], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `relatorio_seguranca_${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    mostrarModal('EXPORTADO', 'Relatório baixado com sucesso!');
}

// Seleção de fonte de log
function selectSource(element) {
    document.querySelectorAll('.source-option').forEach(opt => {
        opt.classList.remove('active');
    });
    element.classList.add('active');
    templateSelector.value = element.dataset.value;
}

// Adicionar novo campo IOC automaticamente
function addNewIocField(input) {
    if (input.value.trim() !== '' &&
        input === input.parentElement.parentElement.lastElementChild.querySelector('input')) {
        addIocField();
    }
}
