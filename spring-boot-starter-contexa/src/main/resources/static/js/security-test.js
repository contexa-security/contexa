'use strict';
(function(){
const API={sse:'/admin/api/sse/llm-analysis/user',status:'/admin/api/test-action/status',evidence:'/admin/api/security-test/evidence',endpoints:{sensitive:'/admin/api/security-test/sensitive/resource-001',critical:'/admin/api/security-test/critical/resource-001'}};
const STORE={access:'contexa_access_token',refresh:'contexa_refresh_token',mode:'authMode'};
const SCENARIO={NORMAL_USER:{title:'정상 사용자',ip:'192.168.1.100',ua:'Chrome 120 / Windows 11 / Corp LAN',expect:'ALLOW 또는 저위험 유지'},ACCOUNT_TAKEOVER:{title:'계정탈취자',ip:'203.0.113.50',ua:'Android 10 / Hijacked Session',expect:'후속 요청 CHALLENGE 또는 BLOCK'}};
const ENDPOINT={sensitive:{title:'민감 리소스',desc:'민감 정보 접근 경로'},critical:{title:'중요 리소스',desc:'최고 중요 정보 접근 경로'}};
const SSE_TYPES=['connected','CONTEXT_COLLECTED','HCAD_ANALYSIS','SESSION_CONTEXT_LOADED','RAG_SEARCH_COMPLETE','BEHAVIOR_ANALYSIS_COMPLETE','LAYER1_START','LAYER1_COMPLETE','LAYER2_START','LAYER2_COMPLETE','LLM_EXECUTION_START','LLM_EXECUTION_COMPLETE','DECISION_APPLIED','RESPONSE_BLOCKED','ERROR'];
const el={};
const st={user:document.body.dataset.username||'anonymous',scenario:'NORMAL_USER',endpoint:'sensitive',runId:null,requestId:null,history:[],events:new Map(),responses:new Map(),evidence:new Map(),truth:null,eventSource:null,auth:{mode:'cookie',source:'none',carrier:'SESSION_COOKIE_ONLY',subject:document.body.dataset.username||'anonymous',attached:false,accessToken:null}};

document.addEventListener('DOMContentLoaded',init);

function init(){
  bindElements();
  bindEvents();
  refreshAuth();
  renderScenario();
  renderRequestHistory();
  renderTimeline();
  renderImmediateResponse();
  renderServerTruth();
  renderEvidence();
  connectSse();
}

function bindElements(){
  ['sse-indicator','sse-text','current-run-id','selected-request-id','auth-transport','auth-token-source','auth-token-state','auth-subject','selected-scenario-name','selected-scenario-ip','selected-scenario-ua','selected-expected-action','selected-endpoint-name','request-header-preview','btn-run-initial','btn-run-follow-up','btn-refresh-server','btn-export-evidence','btn-stream-evidence','btn-reset-console','immediate-response-facts','immediate-response-json','verdict-badge','metric-risk','metric-confidence','metric-depth','metric-context-hash','reasoning-summary','proposed-action','consistency-list','timeline','request-history','server-truth-facts','server-truth-json','context-summary','saas-summary','evidence-links','evidence-json','evidence-stream-output'].forEach(id=>el[toCamel(id)]=document.getElementById(id));
}

function bindEvents(){
  document.querySelectorAll('[data-scenario]').forEach(btn=>btn.addEventListener('click',()=>{st.scenario=btn.dataset.scenario;document.querySelectorAll('[data-scenario]').forEach(x=>x.classList.remove('selected'));btn.classList.add('selected');renderScenario();}));
  document.querySelectorAll('[data-endpoint]').forEach(btn=>btn.addEventListener('click',()=>{st.endpoint=btn.dataset.endpoint;document.querySelectorAll('[data-endpoint]').forEach(x=>x.classList.remove('active'));btn.classList.add('active');renderScenario();}));
  el.btnRunInitial.addEventListener('click',()=>executeRequest('INITIAL'));
  el.btnRunFollowUp.addEventListener('click',()=>executeRequest('FOLLOW_UP'));
  el.btnRefreshServer.addEventListener('click',()=>refreshEvidence(true));
  el.btnExportEvidence.addEventListener('click',exportEvidence);
  el.btnStreamEvidence.addEventListener('click',streamEvidence);
  el.btnResetConsole.addEventListener('click',resetConsole);
}

function connectSse(){
  if(st.eventSource)st.eventSource.close();
  setSseState('connecting','사용자 SSE 연결 중');
  st.eventSource=new EventSource(API.sse);
  SSE_TYPES.forEach(type=>st.eventSource.addEventListener(type,event=>handleSse(type,event)));
  st.eventSource.onopen=()=>setSseState('connected','사용자 SSE 연결됨');
  st.eventSource.onerror=()=>{setSseState('disconnected','사용자 SSE 재연결 중');setTimeout(connectSse,3000);};
}

function handleSse(type,event){
  const payload=asJson(event.data)||{type:type};
  const requestId=payload.requestId||payload.correlationId||'unlinked';
  const list=st.events.get(requestId)||[];
  list.push(payload);
  st.events.set(requestId,list);
  if(requestId===st.requestId){renderTimeline();renderVerdict();}
  if(payload.type==='DECISION_APPLIED'||payload.type==='LAYER2_COMPLETE'||payload.type==='ERROR')refreshEvidence(false);
}

async function executeRequest(phase){
  refreshAuth();
  if(phase==='FOLLOW_UP'&&!st.runId){alert('먼저 1차 요청을 실행하십시오.');return;}
  if(phase==='INITIAL'){st.runId=createId('run');setText(el.currentRunId,st.runId);}
  const scenario=SCENARIO[st.scenario];
  const requestId=createId('req');
  const headers=buildHeaders({'Accept':'application/json','X-Request-ID':requestId,'X-Forwarded-For':scenario.ip,'X-Simulated-User-Agent':scenario.ua,'X-Contexa-Scenario':st.scenario,'X-Contexa-Expected-Action':scenario.expect,'X-Contexa-Demo-Run-Id':st.runId,'X-Contexa-Demo-Phase':phase});
  renderHeaderPreview(headers);
  const response=await fetch(API.endpoints[st.endpoint],{method:'GET',headers:headers,credentials:'same-origin'});
  const body=await parseBody(response);
  const effectiveRequestId=body.requestId||requestId;
  st.requestId=effectiveRequestId;
  setText(el.selectedRequestId,effectiveRequestId);
  st.responses.set(effectiveRequestId,body);
  st.history.unshift({requestId:effectiveRequestId,phase:phase,scenario:st.scenario,status:response.status,body:body,authCarrier:st.auth.carrier});
  renderRequestHistory();
  renderImmediateResponse(body);
  renderEvidenceLinks(body);
  await refreshEvidence(true);
  [800,1800,3200].forEach(delay=>setTimeout(()=>refreshEvidence(false),delay));
}

async function refreshEvidence(includeStream){
  refreshAuth();
  if(!st.requestId)return;
  const [truth,evidence]=await Promise.all([fetchJson(API.status),fetchJson(`${API.evidence}/${st.requestId}`)]);
  st.truth=truth;
  st.evidence.set(st.requestId,evidence);
  renderServerTruth(truth);
  renderEvidence(evidence);
  renderTimeline();
  renderVerdict();
  renderConsistency(evidence,truth);
  if(includeStream)setText(el.evidenceStreamOutput,'NDJSON 스트림은 "증거 NDJSON 보기" 버튼으로 확인합니다.');
}
function exportEvidence(){
  const response=st.responses.get(st.requestId);
  if(!response||!response.evidenceExportUrl){alert('내보낼 evidence가 없습니다.');return;}
  window.open(response.evidenceExportUrl,'_blank','noopener');
}

async function streamEvidence(){
  const response=st.responses.get(st.requestId);
  if(!response||!response.evidenceStreamUrl){alert('스트림할 evidence가 없습니다.');return;}
  setText(el.evidenceStreamOutput,(await fetchText(response.evidenceStreamUrl))||'비어 있습니다.');
}

function resetConsole(){
  st.runId=null;st.requestId=null;st.history=[];st.events.clear();st.responses.clear();st.evidence.clear();st.truth=null;
  setText(el.currentRunId,'미지정');setText(el.selectedRequestId,'없음');
  refreshAuth();renderScenario();renderRequestHistory();renderTimeline();renderImmediateResponse();renderServerTruth();renderEvidence();
}

function renderScenario(){
  const scenario=SCENARIO[st.scenario];
  const endpoint=ENDPOINT[st.endpoint];
  setText(el.selectedScenarioName,scenario.title);
  setText(el.selectedScenarioIp,scenario.ip);
  setText(el.selectedScenarioUa,scenario.ua);
  setText(el.selectedExpectedAction,scenario.expect);
  setText(el.selectedEndpointName,`${endpoint.title} / ${endpoint.desc}`);
  renderHeaderPreview(buildHeaders({'X-Contexa-Scenario':st.scenario,'X-Forwarded-For':scenario.ip,'X-Simulated-User-Agent':scenario.ua,'X-Contexa-Demo-Phase':'INITIAL','X-Contexa-Demo-Run-Id':st.runId||'미지정'}));
}

function renderHeaderPreview(headers){
  const preview={...headers};
  if(preview.Authorization)preview.Authorization=maskBearer(preview.Authorization);
  setHtml(el.requestHeaderPreview,Object.entries(preview).map(([k,v])=>`<div class="header-item"><span>${esc(k)}</span><code>${esc(str(v))}</code></div>`).join(''));
}

function renderImmediateResponse(payload){
  if(!payload){setHtml(el.immediateResponseFacts,facts([]));setText(el.immediateResponseJson,'{}');return;}
  setHtml(el.immediateResponseFacts,facts([['HTTP 상태',payload.httpStatus],['Result Type',payload.resultType],['Request ID',payload.requestId],['Correlation ID',payload.correlationId],['Scenario',payload.scenario],['Phase',payload.demoPhase],['Client IP',payload.clientIp],['Session ID',payload.sessionId],['Auth Carrier',payload.authCarrier],['Auth Mode',payload.authMode],['Auth Subject',payload.authSubjectHint],['Authorization Header',payload.authorizationHeaderPresent]]));
  setText(el.immediateResponseJson,pretty(payload));
}

function renderServerTruth(payload){
  if(!payload){setHtml(el.serverTruthFacts,facts([]));setText(el.serverTruthJson,'{}');return;}
  setHtml(el.serverTruthFacts,facts([['현재 Action',payload.action],['분석 상태',payload.analysisStatus],['Request ID',payload.requestId],['User ID',payload.userId],['Risk',payload.riskScore],['Confidence',payload.confidence],['Context Binding Hash',payload.contextBindingHash],['Threat Evidence',payload.threatEvidence]]));
  setText(el.serverTruthJson,pretty(payload));
}

function renderEvidence(evidence){
  if(!evidence){
    setHtml(el.contextSummary,empty('선택한 evidence가 없습니다.'));
    setHtml(el.saasSummary,empty('선택한 evidence가 없습니다.'));
    setText(el.evidenceJson,'{}');
    setHtml(el.evidenceLinks,'');
    renderConsistency();
    renderVerdict();
    return;
  }
  const request=evidence.request||{};
  const context=evidence.context||{};
  const saas=evidence.saas||{};
  setText(el.evidenceJson,pretty(evidence));
  setHtml(el.contextSummary,[row('Scenario',context.scenario||request.scenario),row('Expected Action',context.expectedAction||request.expectedAction),row('Client IP',context.clientIp||request.clientIp),row('User-Agent',context.userAgent||request.userAgent),row('Session ID',context.sessionId||request.sessionId),row('Context Binding Hash',context.contextBindingHash),row('Auth Carrier',request.authCarrier),row('Auth Mode',request.authMode),row('Auth Subject',request.authSubjectHint),row('Authorization Header',request.authorizationHeaderPresent),row('Recent Session Actions',sizeOf(context.recentSessionActions)),row('Recent Narrative Families',sizeOf(context.recentNarrativeActionFamilies)),row('Recent Protectable Accesses',sizeOf(context.recentProtectableAccesses)),row('Work Profile Observations',sizeOf(context.workProfileObservations)),row('Permission Change Observations',sizeOf(context.permissionChangeObservations)),row('HCAD Session Metadata',sizeOf(context.hcadSessionMetadata)),row('HCAD Analysis',sizeOf(context.hcadAnalysis))].join(''));
  setHtml(el.saasSummary,[card('Security Decision Outbox',[['present',saas.securityDecisionOutbox&&saas.securityDecisionOutbox.present],['status',saas.securityDecisionOutbox&&saas.securityDecisionOutbox.status],['attemptCount',saas.securityDecisionOutbox&&saas.securityDecisionOutbox.attemptCount],['deliveredAt',saas.securityDecisionOutbox&&saas.securityDecisionOutbox.deliveredAt],['correlationId',saas.securityDecisionOutbox&&saas.securityDecisionOutbox.correlationId]]),card('Prompt Context Audit Outbox',[['present',saas.promptContextAuditOutbox&&saas.promptContextAuditOutbox.present],['status',saas.promptContextAuditOutbox&&saas.promptContextAuditOutbox.status],['attemptCount',saas.promptContextAuditOutbox&&saas.promptContextAuditOutbox.attemptCount],['deliveredAt',saas.promptContextAuditOutbox&&saas.promptContextAuditOutbox.deliveredAt],['correlationId',saas.promptContextAuditOutbox&&saas.promptContextAuditOutbox.correlationId]]),card('SaaS Pull Snapshots',[['baselineSeed',snapshotSummary(saas.pullSnapshots&&saas.pullSnapshots.baselineSeed)],['threatIntelligence',snapshotSummary(saas.pullSnapshots&&saas.pullSnapshots.threatIntelligence)],['knowledgePack',snapshotSummary(saas.pullSnapshots&&saas.pullSnapshots.knowledgePack)],['runtimePolicy',snapshotSummary(saas.pullSnapshots&&saas.pullSnapshots.runtimePolicy)]])].join(''));
  renderConsistency(evidence,st.truth);
  renderVerdict();
}

function renderConsistency(evidence,truth){
  if(!evidence){setHtml(el.consistencyList,consistencyItem('대기','선택한 requestId에 대한 evidence가 없습니다.','pending'));return;}
  refreshAuth();
  const response=st.responses.get(st.requestId)||{};
  const request=evidence.request||{};
  const analysis=evidence.analysis||{};
  const consistency=evidence.consistency||{};
  const user=st.auth.subject&&st.auth.subject!=='unknown'?st.auth.subject:st.user;
  setHtml(el.consistencyList,[boolItem('즉시 응답 requestId와 evidence requestId 일치',response.requestId===evidence.requestId),boolItem('즉시 응답 sessionId와 evidence sessionId 일치',response.sessionId===request.sessionId),boolItem('즉시 응답 clientIp와 evidence clientIp 일치',response.clientIp===request.clientIp),boolItem('UI auth carrier와 evidence request auth carrier 일치',!request.authCarrier||request.authCarrier===st.auth.carrier),boolItem('UI auth mode와 evidence request auth mode 일치',!request.authMode||request.authMode===st.auth.mode),boolItem('UI token source와 evidence request token source 일치',!request.tokenSource||request.tokenSource===st.auth.source),boolItem('UI auth subject와 evidence request auth subject 일치',!request.authSubjectHint||request.authSubjectHint===st.auth.subject),boolItem('Authorization 부착 여부가 evidence와 일치',request.authorizationHeaderPresent===undefined||request.authorizationHeaderPresent===st.auth.attached),boolItem('즉시 응답 user와 현재 인증 주체 일치',!response.user||response.user===user),boolItem('서버 truth userId와 현재 인증 주체 일치',!truth||!truth.userId||truth.userId===user),boolItem('서버 truth requestId와 evidence analysis.requestId 일치',!truth||!truth.requestId||truth.requestId===analysis.requestId),boolItem('SSE 이벤트가 현재 requestId와 연결됨',consistency.sseLinked),boolItem('분석 결과가 현재 requestId와 연결됨',consistency.analysisRequestLinked),boolItem('Decision outbox가 현재 requestId와 연결됨',consistency.decisionOutboxLinked),boolItem('Prompt audit outbox가 현재 requestId와 연결됨',consistency.promptAuditLinked),boolItem('Context binding hash가 존재함',consistency.contextBindingPresent),boolItem('서버 truth 준비 완료',consistency.serverTruthReady),boolItem('SaaS evidence 준비 완료',consistency.saasEvidenceReady)].join(''));
}

function renderVerdict(){
  const evidence=st.evidence.get(st.requestId);
  const analysis=evidence?(evidence.analysis||{}):{};
  const events=st.events.get(st.requestId)||[];
  const action=analysis.action||deriveAction(events)||'PENDING_ANALYSIS';
  setText(el.metricRisk,num(analysis.riskScore));
  setText(el.metricConfidence,num(analysis.confidence));
  setText(el.metricDepth,analysis.analysisDepth||'-');
  setText(el.metricContextHash,analysis.contextBindingHash||'-');
  setText(el.reasoningSummary,analysis.reasoningSummary||latestReasoning(events)||'아직 분석 결과가 없습니다.');
  setText(el.proposedAction,analysis.llmProposedAction||action||'-');
  setText(el.verdictBadge,action);
  el.verdictBadge.className=`verdict-badge ${verdictClass(action)}`;
}
function renderTimeline(){
  const events=st.events.get(st.requestId)||[];
  if(!events.length){setHtml(el.timeline,empty('아직 수신한 SSE 이벤트가 없습니다.'));return;}
  setHtml(el.timeline,events.map(event=>`<div class="timeline-item ${timelineClass(event.type)}"><div class="timeline-head"><strong>${esc(event.type||'-')}</strong><span>${esc(formatTimestamp(event.timestamp))}</span></div><div class="timeline-body"><span>layer: ${esc(event.layer||'-')}</span><span>action: ${esc(event.action||'-')}</span><span>risk: ${esc(num(event.riskScore))}</span><span>confidence: ${esc(num(event.confidence))}</span><span>requestId: ${esc(event.requestId||event.correlationId||'-')}</span></div><p class="timeline-summary">${esc(event.reasoningSummary||event.reasoning||'-')}</p></div>`).join(''));
}

function renderRequestHistory(){
  if(!st.history.length){setHtml(el.requestHistory,empty('아직 실행한 요청이 없습니다.'));return;}
  setHtml(el.requestHistory,st.history.map(item=>{const response=item.body||{};const active=response.requestId===st.requestId?'active':'';return `<button type="button" class="history-item ${active}" data-request-id="${esc(response.requestId||item.requestId)}"><div class="history-head"><strong>${esc(item.phase)}</strong><span>${esc(item.scenario)}</span></div><div class="history-body"><span>requestId: ${esc(response.requestId||item.requestId)}</span><span>status: ${esc(str(item.status))}</span><span>sessionId: ${esc(response.sessionId||'-')}</span><span>auth: ${esc(item.authCarrier||'-')}</span></div></button>`;}).join(''));
  el.requestHistory.querySelectorAll('[data-request-id]').forEach(button=>button.addEventListener('click',()=>{st.requestId=button.dataset.requestId;setText(el.selectedRequestId,st.requestId);renderRequestHistory();refreshEvidence(false);}));
}

function renderEvidenceLinks(response){
  if(!response||!response.evidenceUrl){setHtml(el.evidenceLinks,'');return;}
  setHtml(el.evidenceLinks,`<a href="${esc(response.evidenceUrl)}" target="_blank" rel="noopener">evidence JSON</a><a href="${esc(response.evidenceExportUrl)}" target="_blank" rel="noopener">export JSON</a><a href="${esc(response.evidenceStreamUrl)}" target="_blank" rel="noopener">NDJSON stream</a><a href="${esc(response.actionStatusUrl)}" target="_blank" rel="noopener">server truth</a>`);
}

function refreshAuth(){
  restoreTokenMemory();
  const tokenMemory=window.TokenMemory||{};
  const accessToken=pick(tokenMemory.accessToken,safeGet(localStorage,STORE.access),safeGet(sessionStorage,STORE.access));
  const refreshToken=pick(tokenMemory.refreshToken,safeGet(localStorage,STORE.refresh),safeGet(sessionStorage,STORE.refresh));
  const source=resolveTokenSource(tokenMemory,accessToken);
  const mode=pick(safeGet(localStorage,STORE.mode),safeGet(sessionStorage,STORE.mode),accessToken?'header':'cookie');
  const subject=pick(resolveTokenSubject(accessToken),st.user,'unknown');
  const attached=Boolean(accessToken);
  st.auth={mode:mode,source:source,carrier:resolveAuthCarrier(mode,attached),subject:subject,attached:attached,accessToken:accessToken,refreshToken:refreshToken};
  setText(el.authTransport,st.auth.carrier);
  setText(el.authTokenSource,st.auth.source);
  setText(el.authTokenState,attached?'PRESENT':'MISSING');
  setText(el.authSubject,subject);
}

function restoreTokenMemory(){
  const accessToken=pick(safeGet(localStorage,STORE.access),safeGet(sessionStorage,STORE.access));
  const refreshToken=pick(safeGet(localStorage,STORE.refresh),safeGet(sessionStorage,STORE.refresh));
  if(!window.TokenMemory)window.TokenMemory={accessToken:null,refreshToken:null};
  if(!window.TokenMemory.accessToken&&accessToken)window.TokenMemory.accessToken=accessToken;
  if(!window.TokenMemory.refreshToken&&refreshToken)window.TokenMemory.refreshToken=refreshToken;
}

function buildHeaders(base){
  const headers={...base,'X-Contexa-Auth-Mode':st.auth.mode,'X-Contexa-Token-Source':st.auth.source,'X-Contexa-Auth-Carrier':st.auth.carrier,'X-Contexa-Auth-Subject':st.auth.subject,'X-Contexa-Authorization-Present':String(st.auth.attached)};
  if(st.auth.accessToken)headers.Authorization=`Bearer ${st.auth.accessToken}`;
  return headers;
}

function resolveTokenSource(tokenMemory,accessToken){
  if(tokenMemory&&tokenMemory.accessToken&&tokenMemory.accessToken===accessToken)return'memory';
  if(safeGet(localStorage,STORE.access)===accessToken&&accessToken)return'localStorage';
  if(safeGet(sessionStorage,STORE.access)===accessToken&&accessToken)return'sessionStorage';
  return'none';
}

function resolveTokenSubject(token){
  const payload=decodeJwtPayload(token);
  return payload?pick(payload.sub,payload.username,payload.user_name):null;
}

function decodeJwtPayload(token){
  if(!token)return null;
  const parts=token.split('.');
  if(parts.length!==3)return null;
  try{
    const normalized=parts[1].replace(/-/g,'+').replace(/_/g,'/');
    const padded=normalized+'='.repeat((4-normalized.length%4)%4);
    return JSON.parse(window.atob(padded));
  }catch(error){return null;}
}

function resolveAuthCarrier(mode,attached){
  if(attached)return'SESSION_COOKIE + BEARER';
  if(mode==='header'||mode==='header_cookie')return'SESSION_COOKIE_ONLY (TOKEN_MISSING)';
  return'SESSION_COOKIE_ONLY';
}

async function fetchJson(url){
  const response=await fetch(url,{headers:buildHeaders({'Accept':'application/json'}),credentials:'same-origin'});
  return parseBody(response);
}

async function fetchText(url){
  const response=await fetch(url,{headers:buildHeaders({'Accept':'application/x-ndjson, text/plain, application/json'}),credentials:'same-origin'});
  return response.text();
}
async function parseBody(response){
  const text=await response.text();
  return asJson(text)||{raw:text,httpStatus:response.status};
}

function asJson(text){if(!text)return null;try{return JSON.parse(text);}catch(error){return null;}}
function boolItem(label,passed){return consistencyItem(label,passed?'일치':'불일치',passed?'pass':'fail');}
function consistencyItem(label,text,kind){return `<div class="consistency-item ${kind}"><strong>${esc(label)}</strong><span>${esc(text)}</span></div>`;}
function card(title,pairs){return `<article class="summary-card"><h3>${esc(title)}</h3>${pairs.map(([k,v])=>row(k,v)).join('')}</article>`;}
function row(label,value){return `<div class="summary-row"><span>${esc(label)}</span><strong>${esc(str(value))}</strong></div>`;}
function facts(items){if(!items.length)return'<div><dt>상태</dt><dd>없음</dd></div>';return items.map(([k,v])=>`<div><dt>${esc(k)}</dt><dd>${esc(str(v))}</dd></div>`).join('');}
function deriveAction(events){const last=[...events].reverse().find(event=>event.action);return last?last.action:null;}
function latestReasoning(events){const last=[...events].reverse().find(event=>event.reasoningSummary||event.reasoning);return last?(last.reasoningSummary||last.reasoning):null;}
function snapshotSummary(snapshot){if(!snapshot)return'없음';const keys=Object.keys(snapshot).filter(key=>snapshot[key]!==null&&snapshot[key]!==undefined);if(!keys.length)return'없음';return keys.slice(0,3).map(key=>`${key}=${str(snapshot[key])}`).join(', ');}
function verdictClass(action){const normalized=(action||'').toUpperCase();if(normalized.includes('BLOCK'))return'block';if(normalized.includes('CHALLENGE'))return'challenge';if(normalized.includes('ESCALATE'))return'escalate';if(normalized.includes('ALLOW'))return'allow';return'pending';}
function timelineClass(type){if(type==='ERROR')return'error';if(type==='DECISION_APPLIED'||type==='RESPONSE_BLOCKED')return'decision';if(type&&type.includes('LAYER2'))return'layer2';if(type&&type.includes('LAYER1'))return'layer1';return'context';}
function maskBearer(value){if(!value||!value.startsWith('Bearer '))return value;const token=value.slice(7);return token.length<=16?'Bearer <attached>':`Bearer ${token.slice(0,8)}...${token.slice(-8)}`;}
function createId(prefix){return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2,8)}`;}
function formatTimestamp(value){return value?new Date(value).toLocaleTimeString('ko-KR',{hour12:false}):'-';}
function pretty(value){return JSON.stringify(value,null,2);}
function sizeOf(value){if(Array.isArray(value))return value.length;if(value&&typeof value==='object')return Object.keys(value).length;return value??'-';}
function num(value){return value===null||value===undefined||Number.isNaN(Number(value))?'-':Number(value).toFixed(2);}
function str(value){if(value===null||value===undefined||value==='')return'-';return typeof value==='object'?JSON.stringify(value):String(value);}
function pick(){for(let i=0;i<arguments.length;i+=1){const value=arguments[i];if(typeof value==='string'&&value.trim()!=='')return value.trim();}return null;}
function safeGet(storage,key){try{return storage?storage.getItem(key):null;}catch(error){return null;}}
function setSseState(kind,text){el.sseIndicator.className=`status-dot ${kind}`;setText(el.sseText,text);}
function setHtml(node,value){node.innerHTML=value;}
function setText(node,value){node.textContent=value;}
function empty(message){return `<div class="empty-state">${esc(message)}</div>`;}
function esc(value){return String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function toCamel(id){return id.replace(/-([a-z])/g,(_,ch)=>ch.toUpperCase());}
})();
