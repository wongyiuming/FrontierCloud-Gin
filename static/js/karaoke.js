'use strict';

const MAX_RECORDING_BYTES = 256 * 1024 * 1024;
const elements = Object.fromEntries([
  'back', 'kind', 'title', 'original', 'accompaniment', 'media', 'lyrics',
  'record', 'pauseResume', 'stop', 'upload', 'fullLyrics', 'status', 'inputDevice', 'outputDevice',
  'refreshDevices', 'songGain', 'songValue', 'songMute', 'voiceGain', 'voiceValue',
  'monitorGain', 'monitorValue', 'monitor', 'aec', 'capabilities', 'previewCard',
  'preview', 'previewHint', 'lyricsOverlay', 'overlayLines', 'account', 'accountName',
].map(id => [id, document.getElementById(id)]));

const state = {
  ready: false,
  phase: 'idle',
  context: null,
  lyrics: [],
  sourceLyrics: [],
  sourceLyricsEncrypted: false,
  sourceLyricsStatus: 'unlinked',
  recordingSnapshot: null,
  activeLyric: -2,
  audioContext: null,
  graph: null,
  microphone: null,
  recorder: null,
  chunks: [],
  recordedBytes: 0,
  previewUrl: null,
  accompaniment: false,
  recordedBlob: null,
  account: null,
  accountStatus: null,
  recordingUpload: null,
  recordingUploadBusy: false,
  recordingPlaybackUser: null,
  recordingPreviewID: null,
  authMode: 'login',
};

function errorText(error) {
  if (!error) return '未知错误';
  const name = error.name && error.name !== 'Error' ? `${error.name}: ` : '';
  return `${name}${error.message || String(error)}`;
}

function setStatus(message, isError = false) {
  elements.status.textContent = message;
  elements.status.style.color = isError ? '#ff9f9f' : '';
}

function percentage(id) {
  return Number(elements[id].value) / 100;
}

function applyLevels() {
  if (!state.graph) return;
  state.graph.songGain.gain.value = elements.songMute.checked ? 0 : percentage('songGain');
  state.graph.recordGain.gain.value = Math.min(6, Math.max(0, percentage('voiceGain')));
  state.graph.monitorGain.gain.value = elements.monitor.checked
    ? Math.min(2, Math.max(0, percentage('monitorGain')))
    : 0;
}

function setAccompaniment(enabled) {
  state.accompaniment = enabled;
  elements.original.classList.toggle('selected', !enabled);
  elements.accompaniment.classList.toggle('selected', enabled);
  if (!state.graph) return;
  state.graph.mediaSource.disconnect();
  state.graph.mediaSource.connect(enabled ? state.graph.splitter : state.graph.songGain);
}

function prepareAudioGraph() {
  if (state.graph) {
    void state.audioContext.resume();
    return state.graph;
  }
  const AudioContextClass = window.AudioContext || window.webkitAudioContext;
  const context = new AudioContextClass({latencyHint: 'interactive'});
  state.audioContext = context;
  void context.resume();

  const songGain = context.createGain();
  songGain.connect(context.destination);

  const highPass = context.createBiquadFilter();
  highPass.type = 'highpass';
  highPass.frequency.value = 80;
  const lowPass = context.createBiquadFilter();
  lowPass.type = 'lowpass';
  lowPass.frequency.value = 14000;
  highPass.connect(lowPass);

  const recordGain = context.createGain();
  const limiter = context.createDynamicsCompressor();
  limiter.threshold.value = -3;
  limiter.knee.value = 6;
  limiter.ratio.value = 12;
  limiter.attack.value = 0.003;
  limiter.release.value = 0.25;
  const recordDestination = context.createMediaStreamDestination();
  lowPass.connect(recordGain);
  recordGain.connect(limiter);
  limiter.connect(recordDestination);

  const monitorGain = context.createGain();
  monitorGain.gain.value = 0;
  lowPass.connect(monitorGain);
  monitorGain.connect(context.destination);

  const splitter = context.createChannelSplitter(2);
  const left = context.createGain();
  const right = context.createGain();
  right.gain.value = -1;
  const merger = context.createChannelMerger(2);
  splitter.connect(left, 0);
  splitter.connect(right, 1);
  left.connect(merger, 0, 0);
  right.connect(merger, 0, 0);
  left.connect(merger, 0, 1);
  right.connect(merger, 0, 1);
  merger.connect(songGain);

  // This binding may only be created once for a media element. Store it before
  // any later asynchronous work so repeated record clicks always reuse it.
  const mediaSource = context.createMediaElementSource(elements.media);
  const graph = {
    context, songGain, highPass, lowPass, recordGain, limiter, recordDestination,
    monitorGain, splitter, mediaSource, microphoneSource: null,
  };
  state.graph = graph;
  mediaSource.connect(state.accompaniment ? splitter : songGain);
  applyLevels();
  void applyOutputDevice();
  return graph;
}

function microphoneConstraints() {
  const audio = {
    echoCancellation: elements.aec.checked,
    noiseSuppression: false,
    autoGainControl: false,
    channelCount: 1,
  };
  if (elements.inputDevice.value) audio.deviceId = {exact: elements.inputDevice.value};
  return {audio, video: false};
}

async function openMicrophone() {
  return navigator.mediaDevices.getUserMedia(microphoneConstraints());
}

function replaceMicrophone(stream) {
  const graph = prepareAudioGraph();
  if (graph.microphoneSource) graph.microphoneSource.disconnect();
  graph.microphoneSource = graph.context.createMediaStreamSource(stream);
  graph.microphoneSource.connect(graph.highPass);
}

function stopMicrophone() {
  if (!state.microphone) return;
  for (const track of state.microphone.getTracks()) track.stop();
  state.microphone = null;
}

function clearPreview() {
  elements.preview.pause();
  elements.preview.removeAttribute('src');
  state.recordingPreviewID = null;
  if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
  state.previewUrl = null;
  state.recordedBlob = null;
  state.recordingSnapshot = null;
  elements.previewCard.hidden = true;
}

function preferredRecordingOptions() {
  for (const mimeType of ['audio/webm;codecs=opus', 'audio/webm', 'audio/ogg;codecs=opus']) {
    if (MediaRecorder.isTypeSupported(mimeType)) return {mimeType};
  }
  return undefined;
}

function resetFailedStart(message) {
  state.phase = 'idle';
  state.recordingSnapshot = null;
  showLyrics(state.sourceLyrics);
  elements.record.disabled = false;
  elements.stop.disabled = true;
  elements.aec.disabled = false;
  stopMicrophone();
  setStatus(`无法开始录音：${message}`, true);
}

function recordingTitle(value) {
  // Match the server's Unicode TrimSpace before signing/storing one footer.
  return String(value || '').replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '') || '卡拉OK录音';
}

async function addRecordingMetadata(blob, snapshot = state.recordingSnapshot, encryptedLyrics = null) {
  // Guests retain encrypted-source lyrics only in page memory. Saving an
  // opaque footer requires an authenticated preparation and browser encryption.
  const encrypted = snapshot?.encrypted ?? state.sourceLyricsEncrypted;
  if (encrypted && !encryptedLyrics) return blob;
  return appendRecordingFooter(blob, {
    version: 1, title: recordingTitle(snapshot?.title || state.context?.title),
    lyrics: encrypted ? [] : snapshot?.lyrics || state.lyrics,
    ...(encryptedLyrics ? {encrypted_lyrics: encryptedLyrics} : {}),
  });
}

function appendRecordingFooter(blob, metadata) {
  const encoded = new TextEncoder().encode(JSON.stringify(metadata));
  if (encoded.byteLength > 2 * 1024 * 1024) throw new Error('录音元数据超过 2 MiB 限制');
  const length = new Uint8Array(8);
  new DataView(length.buffer).setBigUint64(0, BigInt(encoded.byteLength));
  return new Blob([blob, encoded, length, new TextEncoder().encode('FRONTIERCLOUD-KARAOKE-V1')], {type: blob.type});
}

async function finishRecording() {
  const mimeType = state.recorder?.mimeType || state.chunks[0]?.type || 'audio/webm';
  const blob = await addRecordingMetadata(new Blob(state.chunks, {type: mimeType}));
  state.chunks = [];
  state.recordedBytes = 0;
  state.previewUrl = URL.createObjectURL(blob);
  state.recordedBlob = blob;
  elements.preview.src = state.previewUrl;
  elements.previewCard.hidden = false;
  state.phase = 'preview';
  elements.record.disabled = true;
  elements.pauseResume.disabled = false;
  elements.pauseResume.textContent = '暂停';
  elements.stop.disabled = true;
  elements.aec.disabled = false;
  state.recorder = null;
  stopMicrophone();
  updateRecordingUploadControls();
  elements.previewHint.textContent = state.recordingSnapshot?.encrypted
    ? '加密来源歌词当前仅在本页面内存中；登录上传后会以加密快照保存。' : '';
  setStatus(state.account ? '录音已停止，可试听或上传到个人空间。' : '录音已停止；登录后可上传，当前可试听。');
  void applyOutputDevice();
}

async function startRecording() {
  if (!state.ready) return;
  if (state.phase === 'initializing' || state.phase === 'recording') return;
  state.phase = 'initializing';
  elements.record.disabled = true;
  elements.stop.disabled = true;
  elements.aec.disabled = true;
  clearPreview();
  state.recordingSnapshot = {
    encrypted: state.sourceLyricsEncrypted,
    lyrics: state.sourceLyrics.map(entry => ({time: entry.time, text: entry.text})),
    title: recordingTitle(state.context?.title),
    media: new URLSearchParams(location.search).get('media'),
  };
  showLyrics(state.recordingSnapshot.lyrics);
  setStatus('正在初始化麦克风和纯人声录音支路…');
  try {
    // Create and retain the media binding synchronously inside the trusted click.
    // Every later recording reuses this graph and replaces only the microphone.
    prepareAudioGraph();
    stopMicrophone();
    const stream = await openMicrophone();
    state.microphone = stream;
    replaceMicrophone(stream);
    await state.audioContext.resume();
    await applyOutputDevice();

    state.chunks = [];
    state.recordedBytes = 0;
    const recorder = new MediaRecorder(state.graph.recordDestination.stream, preferredRecordingOptions());
    state.recorder = recorder;
    recorder.addEventListener('dataavailable', event => {
      if (!event.data?.size) return;
      state.recordedBytes += event.data.size;
      if (state.recordedBytes > MAX_RECORDING_BYTES) {
        setStatus('录音达到 256MB 安全上限，已自动停止。', true);
        if (recorder.state !== 'inactive') recorder.stop();
        return;
      }
      state.chunks.push(event.data);
    });
    recorder.addEventListener('stop', finishRecording, {once: true});
    recorder.addEventListener('error', event => {
      resetFailedStart(errorText(event.error));
    }, {once: true});
    recorder.start(1000);
    state.phase = 'recording';
    elements.stop.disabled = false;
    elements.pauseResume.disabled = false;
    setStatus('正在录制纯人声支路；媒体和返听数字信号不会进入录音。');
    elements.media.play().catch(error => {
      setStatus(`录音继续，但媒体播放失败：${errorText(error)}`, true);
    });
  } catch (error) {
    resetFailedStart(errorText(error));
  }
}

function stopRecording() {
  if (state.recorder?.state !== 'inactive') state.recorder.stop();
  elements.media.pause();
}

function pauseResume() {
  if (state.phase === 'recording' && state.recorder) {
    if (state.recorder.state === 'recording') {
      state.recorder.pause(); elements.media.pause(); elements.pauseResume.textContent = '恢复';
      setStatus('录音与媒体已暂停。');
    } else if (state.recorder.state === 'paused') {
      state.recorder.resume(); elements.media.play().catch(() => {}); elements.pauseResume.textContent = '暂停';
      setStatus('录音与媒体已恢复。');
    }
    return;
  }
  if (state.phase === 'preview') {
    if (elements.preview.paused) {
      elements.preview.play().then(() => { elements.pauseResume.textContent = '暂停'; })
        .catch(error => setStatus(errorText(error), true));
    } else {
      elements.preview.pause(); elements.pauseResume.textContent = '恢复';
    }
  }
}

async function applyOutputDevice() {
  const sinkId = elements.outputDevice.value;
  if (!sinkId) return;
  if (state.audioContext && typeof state.audioContext.setSinkId === 'function') {
    await state.audioContext.setSinkId(sinkId);
  }
  if (typeof elements.preview.setSinkId === 'function') await elements.preview.setSinkId(sinkId);
}

function fillDeviceOptions(select, devices, defaultLabel, fallbackLabel) {
  const selected = select.value;
  select.replaceChildren(new Option(defaultLabel, ''));
  devices.forEach((device, index) => select.add(new Option(device.label || `${fallbackLabel} ${index + 1}`, device.deviceId)));
  if ([...select.options].some(option => option.value === selected)) select.value = selected;
}

async function refreshDevices() {
  const permission = await openMicrophone();
  permission.getTracks().forEach(track => track.stop());
  const devices = await navigator.mediaDevices.enumerateDevices();
  fillDeviceOptions(elements.inputDevice, devices.filter(device => device.kind === 'audioinput'), '系统默认麦克风', '麦克风');
  fillDeviceOptions(elements.outputDevice, devices.filter(device => device.kind === 'audiooutput'), '系统默认输出', '输出设备');
  setStatus('输入和输出设备列表已刷新。');
}

function activeLyricIndex(time) {
  let low = 0;
  let high = state.lyrics.length - 1;
  let found = -1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    if (Number(state.lyrics[middle].time) <= time) {
      found = middle;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return found;
}

function renderEmptyLyrics(container) {
  container.replaceChildren();
  const line = document.createElement('p');
  const sourceNotice = {
    unlinked: '当前媒体没有已关联歌词。',
    loading: '正在载入歌词，可开始卡拉OK。',
    unavailable: '歌词暂不可用，可开始卡拉OK。',
    ready: '当前歌词没有可显示的内容。',
  };
  line.textContent = state.recordingSnapshot || state.recordingPreviewID
    ? '本次录音暂无歌词。' : sourceNotice[state.sourceLyricsStatus];
  container.append(line);
}

function renderLyricContainer(container, active) {
  if (!state.lyrics.length) {
    renderEmptyLyrics(container);
    return;
  }
  container.replaceChildren();
  const center = Math.max(0, active);
  const start = Math.max(0, center - 1);
  for (let index = start; index < Math.min(state.lyrics.length, start + 4); index += 1) {
    const line = document.createElement('p');
    line.textContent = state.lyrics[index].text;
    if (index === active) line.className = 'current';
    container.append(line);
  }
}

function showLyrics(lyrics) {
  state.lyrics = lyrics;
  state.activeLyric = -2;
  renderLyrics(-1);
}

function renderLyrics(active) {
  // Preserve the inline loading/error notice even when karaoke-ui wraps the renderer.
  if (state.lyrics.length) renderLyricContainer(elements.lyrics, active);
  else renderEmptyLyrics(elements.lyrics);
  renderLyricContainer(elements.overlayLines, active);
}

function lyricClock() {
  const clock = (!elements.preview.paused && elements.preview.currentSrc) ? elements.preview : elements.media;
  const active = activeLyricIndex(clock.currentTime);
  if (active !== state.activeLyric) {
    state.activeLyric = active;
    renderLyrics(active);
  }
  requestAnimationFrame(lyricClock);
}

function capabilityReport() {
  const AudioContextClass = window.AudioContext || window.webkitAudioContext;
  const missing = [];
  if (!AudioContextClass) missing.push('AudioContext');
  if (!navigator.mediaDevices?.getUserMedia) missing.push('麦克风访问');
  if (!window.MediaRecorder) missing.push('MediaRecorder');
  if (missing.length) throw new Error(`当前浏览器缺少：${missing.join('、')}`);

  const supported = navigator.mediaDevices.getSupportedConstraints?.() || {};
  if (!supported.echoCancellation) elements.aec.checked = false;
  const outputSelection = typeof AudioContextClass.prototype.setSinkId === 'function';
  elements.outputDevice.disabled = !outputSelection;
  elements.capabilities.textContent = `AEC ${supported.echoCancellation ? '可用' : '降级'} · 输出设备选择 ${outputSelection ? '可用' : '使用系统默认'} · 触控点 ${navigator.maxTouchPoints || 0}`;
}

async function initialize() {
  capabilityReport();
  const mediaId = new URLSearchParams(location.search).get('media');
  if (!mediaId) throw new Error('缺少当前媒体身份');
  const response = await fetch(`/api/v1/karaoke/context?media=${encodeURIComponent(mediaId)}`, {cache: 'no-store'});
  if (!response.ok) throw new Error(`无法读取当前媒体（HTTP ${response.status}）`);
  state.context = await response.json();
  elements.title.textContent = state.context.title;
  elements.kind.textContent = state.context.type === 'video' ? '视频' : '音乐';
  if (state.context.encryption || state.context.encrypted || state.context.transport === 'S3' || state.context.native_source) {
    if (!window.FrontierMediaCrypto) throw new Error('浏览器解密组件未加载');
    const source = {...state.context, media_path: state.context.file_path};
    await window.FrontierMediaCrypto.prepareCatalog([source]);
    state.context.stream_url = source.url;
  }
  elements.media.src = state.context.stream_url;
  if (state.context.type === 'audio') elements.media.style.display = 'none';
  setStatus('浏览器能力检查通过。授权设备后即可开始 卡拉OK。');
}

async function loadOptionalLyrics() {
  if (!state.context.has_lyrics || !state.context.lyrics_url) {
    elements.fullLyrics.disabled = true;
    showLyrics(state.sourceLyrics);
    return;
  }
  state.sourceLyricsStatus = 'loading';
  showLyrics(state.sourceLyrics);
  try {
    const lyricResponse = await fetch(state.context.lyrics_url, {cache: 'no-store'});
    if (!lyricResponse.ok) throw new Error(`无法读取歌词（HTTP ${lyricResponse.status}）`);
    const payload = await lyricResponse.json();
    if (payload.native_lyric || payload.encrypted && payload.native_source) {
      if (!window.FrontierMediaCrypto) throw new Error('浏览器解密组件未加载');
      const text = await window.FrontierMediaCrypto.lyricTextFor(payload);
      payload.entries = window.FrontierMediaCrypto.parseLyrics(text);
    } else if (payload.encrypted) {
      const text = await window.FrontierMediaCrypto.textFor(payload.lyric_path || payload.file_path, payload.encryption?.file_id);
      payload.entries = window.FrontierMediaCrypto.parseLyrics(text);
    }
    state.sourceLyrics = Array.isArray(payload.entries) ? payload.entries : [];
    state.sourceLyricsEncrypted = Boolean(payload.encrypted);
    state.sourceLyricsStatus = 'ready';
  } catch {
    state.sourceLyricsStatus = 'unavailable';
  }
  if (state.phase === 'idle' && !state.recordingPreviewID) showLyrics(state.sourceLyrics);
}

elements.back.addEventListener('click', () => {
  if (history.length > 1) history.back();
  else location.assign('/api/v1/media');
});
elements.record.addEventListener('click', startRecording);
elements.pauseResume.addEventListener('click', pauseResume);
elements.stop.addEventListener('click', stopRecording);
elements.refreshDevices.addEventListener('click', () => refreshDevices().catch(error => setStatus(`无法读取设备：${errorText(error)}`, true)));
elements.outputDevice.addEventListener('change', () => applyOutputDevice().catch(error => setStatus(`无法切换输出设备：${errorText(error)}`, true)));
elements.inputDevice.addEventListener('change', () => {
  if (state.phase === 'recording') {
    stopRecording();
    setStatus('输入设备已变化，本次录音已安全停止。', true);
  }
});
elements.original.addEventListener('click', () => {
  setAccompaniment(false);
  setStatus('已选择原唱。');
});
elements.accompaniment.addEventListener('click', () => {
  setAccompaniment(true);
  setStatus('已选择中置消除伴奏；不同音源的分离效果会有差异。');
});
for (const [input, output] of [['songGain', 'songValue'], ['voiceGain', 'voiceValue'], ['monitorGain', 'monitorValue']]) {
  elements[input].addEventListener('input', () => {
    elements[output].textContent = `${elements[input].value}%`;
    applyLevels();
  });
}
elements.songMute.addEventListener('change', applyLevels);
elements.monitor.addEventListener('change', applyLevels);
navigator.mediaDevices?.addEventListener?.('devicechange', () => {
  if (state.phase === 'recording') stopRecording();
  setStatus('音频设备已变化，录音已安全停止；请刷新设备后继续。', true);
});

const accountElements = Object.fromEntries([
  'accountModal', 'accountClose', 'guestAccount', 'profile', 'showLogin', 'showRegister',
  'authForm', 'authUsername', 'authPassword', 'authSubmit', 'authMessage', 'captchaRow',
  'captchaImage', 'captchaValue', 'captchaRefresh', 'profileSummary',
  'bindStorage', 'recordingStorageControl', 'recordingStorageStatus', 'retryRecordingUpload',
  'uploadFile', 'uploadFileInput', 'logoutAccount', 'passwordForm',
  'currentPassword', 'newPassword', 'recordingList', 'deleteAccount', 'storageModal',
].map(id => [id, document.getElementById(id)]));

function cookie(name) {
  return document.cookie.split(';').map(item => item.trim()).find(item => item.startsWith(`${name}=`))?.split('=').slice(1).join('=') || '';
}

function karaokeHeaders(json = true) {
  const headers = {};
  if (json) headers['Content-Type'] = 'application/json';
  const name = location.protocol === 'https:' ? '__Host-karaoke_csrf' : 'karaoke_csrf';
  const token = decodeURIComponent(cookie(name));
  if (token) headers['X-Karaoke-CSRF'] = token;
  return headers;
}

async function accountApi(path, options = {}) {
  const response = await fetch(`/api/v1/karaoke/account${path}`, {cache: 'no-store', ...options});
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.detail || `请求失败（HTTP ${response.status}）`);
    error.status = response.status;
    error.captchaRequired = response.headers.get('X-Captcha-Required') === '1';
    error.storageRequired = response.headers.get('X-Storage-Binding-Required') === '1';
    throw error;
  }
  return payload;
}

async function loadCaptcha() {
  const data = await accountApi('/captcha');
  accountElements.captchaImage.dataset.challenge = data.challenge;
  accountElements.captchaImage.src = `${data.image_url}?v=${Date.now()}`;
  accountElements.captchaValue.value = '';
}

function showCaptcha(show) {
  accountElements.captchaRow.hidden = !show;
  accountElements.captchaValue.required = show;
  if (show) loadCaptcha().catch(error => { accountElements.authMessage.textContent = errorText(error); });
}

function setAuthMode(mode) {
  state.authMode = mode;
  accountElements.showLogin.classList.toggle('selected', mode === 'login');
  accountElements.showRegister.classList.toggle('selected', mode === 'register');
  accountElements.authSubmit.textContent = mode === 'login' ? '登录' : '注册';
  accountElements.authPassword.autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  accountElements.authMessage.textContent = mode === 'register' ? '密码需包含大小写字母、数字和特殊字符，至少 10 位。' : '';
  showCaptcha(mode === 'register');
}

function sealedRecordingUpload() {
  return state.accountStatus?.recording_upload_protocol === 'sealed-v1';
}

function recordingDestinations() {
  const {storage_available: available, recording_destinations: destinations} = state.accountStatus || {};
  if (!sealedRecordingUpload() || available !== true || !Array.isArray(destinations)) return [];
  return destinations.filter(item => {
    if (item?.transport !== 'Direct' || typeof item.address !== 'string'
        || typeof item.member_id !== 'string' || !/^[a-f0-9]{32}$/.test(item.member_id)) return false;
    try {
      const address = new URL(item.address);
      return address.protocol === 'https:' && address.origin === item.address;
    } catch (_) {
      return false;
    }
  });
}

function updateRecordingUploadControls() {
  const sealed = sealedRecordingUpload();
  const select = accountElements.bindStorage;
  const selected = select.value;
  const destinations = recordingDestinations();
  const task = state.recordingUpload;
  const canResume = Boolean(task && task.userID === state.account?.user_id);
  if (sealed) {
    select.replaceChildren(new Option('请选择录音存储节点', ''));
    for (const item of destinations) select.add(new Option(item.address, item.member_id));
    select.value = destinations.some(item => item.member_id === selected) ? selected : '';
    accountElements.recordingStorageStatus.textContent = (canResume && task.recoveryMessage)
      || (destinations.length ? '选择本次录音的存储节点。' : '录音存储暂不可用。');
  } else {
    accountElements.recordingStorageStatus.textContent = '录音由 Master Storage Scheduler 自动选择可写存储成员。';
  }
  accountElements.recordingStorageControl.hidden = !sealed || !destinations.length;
  const blocked = state.recordingUploadBusy || Boolean(state.recordingUpload);
  select.disabled = !destinations.length || blocked;
  const canUpload = Boolean(state.account) && !blocked && (!sealed || Boolean(select.value));
  elements.upload.disabled = !canUpload || !state.recordedBlob;
  accountElements.uploadFile.disabled = !canUpload;
  accountElements.retryRecordingUpload.hidden = !canResume;
  accountElements.retryRecordingUpload.disabled = !canResume || state.recordingUploadBusy
    || !destinations.some(item => item.member_id === task.memberID && item.address === task.origin);
}

function renderAccount() {
  const authenticated = Boolean(state.account);
  elements.accountName.textContent = authenticated ? state.account.username : '游客';
  elements.account.textContent = authenticated ? '个人主页' : '登录 / 注册';
  updateRecordingUploadControls();
  accountElements.guestAccount.hidden = authenticated;
  accountElements.profile.hidden = !authenticated;
  if (authenticated) {
    accountElements.deleteAccount.textContent = sealedRecordingUpload() ? '注销账号' : '注销账号并删除全部录音';
    accountElements.profileSummary.textContent = `${state.account.username} · 已用 ${(state.account.used_bytes / 1048576).toFixed(1)} / ${(state.account.quota_bytes / 1048576).toFixed(1)} MiB`;
  }
}

async function refreshAccount() {
  state.accountStatus = await accountApi('/status');
  state.account = state.accountStatus.user || null;
  if (state.recordingPlaybackUser && state.recordingPlaybackUser !== state.account?.user_id) {
    window.FrontierMediaCrypto?.forgetRecordingPlayback?.();
    stopRecordingPreview();
    state.recordingPlaybackUser = null;
  }
  if (state.recordingUpload && state.recordingUpload.userID !== state.account?.user_id) {
    const previous = state.recordingUpload;
    state.recordingUpload = null;
    await previous.encrypted.cleanup();
  }
  renderAccount();
  if (state.account) await loadRecordings();
}

function recordingButton(label, handler) {
  const button = document.createElement('button'); button.type = 'button'; button.textContent = label;
  button.onclick = async () => {
    button.disabled = true;
    try { await handler(); }
    catch (error) { setStatus(errorText(error), true); }
    finally { button.disabled = false; }
  };
  return button;
}

function stopRecordingPreview(id) {
  if (!state.recordingPreviewID || id !== undefined && id !== state.recordingPreviewID) return;
  state.recordingPreviewID = null;
  elements.preview.pause();
  elements.preview.removeAttribute('src');
  elements.previewCard.hidden = true;
  state.lyrics = [];
  state.activeLyric = -2;
}

async function openSealedRecording(id, download = false) {
  const userID = state.account?.user_id;
  if (!userID || !/^[a-f0-9]{32}$/.test(id || '') || !window.FrontierMediaCrypto?.recordingPlayback)
    throw new Error('录音读取暂不可用');
  state.recordingPlaybackUser = userID;
  const authorize = fields => {
    if (state.account?.user_id !== userID) throw new Error('录音账号已变化');
    return accountApi(`/recordings/${id}/audio-key`, {method: 'POST', headers: karaokeHeaders(),
      credentials: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer', body: JSON.stringify(fields)});
  };
  const result = await window.FrontierMediaCrypto.recordingPlayback(id, authorize, download);
  if (state.account?.user_id !== userID) throw new Error('录音账号已变化');
  return result;
}

async function loadRecordings() {
  const sealed = sealedRecordingUpload();
  if (sealed && state.accountStatus.recording_read_available !== true) {
    accountElements.recordingList.textContent = '录音存储暂不可用。';
    return;
  }
  const userID = state.account?.user_id;
  const data = await accountApi('/recordings');
  if (state.account?.user_id !== userID) return;
  accountElements.recordingList.replaceChildren();
  for (const item of data.items) {
    const deleting = sealed && item.state === 'deleting';
    const pending = sealed && item.state === 'pending';
    const row = document.createElement('div'); row.className = 'recording-item';
    const info = document.createElement('div');
    const label = item.filename || `录音 ${item.recording_id.slice(0, 8)}`;
    const name = document.createElement('strong'); name.textContent = label;
    const detail = document.createElement('small'); detail.textContent = `${(item.size_bytes / 1048576).toFixed(1)} MiB · ${new Date(item.created_at * 1000).toLocaleString()}`;
    if (sealed && /^[a-f0-9]{32}$/.test(item.storage_member_id || '')) {
      const owner = recordingDestinations().find(destination => destination.member_id === item.storage_member_id);
      detail.textContent += ` · ${owner?.address || item.storage_member_id.slice(0, 8)}`;
      detail.title = item.storage_member_id;
    }
    if (deleting || pending) detail.textContent += deleting ? ' · 清理待完成' : ' · 等待上传确认';
    info.append(name, detail);
    const actions = document.createElement('div'); actions.className = 'recording-actions';
    if (!deleting && !pending) actions.append(
      recordingButton('试听', async () => {
        if (sealedRecordingUpload()) {
          const playback = await openSealedRecording(item.recording_id);
          state.recordingPreviewID = item.recording_id;
          state.lyrics = playback.lyrics;
          elements.preview.src = playback.url;
        } else {
          state.lyrics = item.encrypted_lyrics
            ? await window.FrontierMediaCrypto.decryptRecordingLyrics(fields => accountApi(`/recordings/${item.recording_id}/lyrics-key`, {
              method: 'POST', headers: karaokeHeaders(), body: JSON.stringify(fields),
            })) : Array.isArray(item.lyrics) ? item.lyrics : [];
          elements.preview.src = `/api/v1/karaoke/account/recordings/${item.recording_id}/stream`;
        }
        state.activeLyric = -2;
        elements.previewCard.hidden = false; elements.previewHint.textContent = item.filename;
        await elements.preview.play(); accountElements.accountModal.hidden = true;
      }),
      recordingButton('下载', async () => {
        const anchor = document.createElement('a');
        if (sealedRecordingUpload()) {
          const download = await openSealedRecording(item.recording_id, true);
          anchor.href = download.url; anchor.download = download.filename;
        } else {
          anchor.href = `/api/v1/karaoke/account/recordings/${item.recording_id}/download`; anchor.download = item.filename;
        }
        anchor.click();
      }),
    );
    if (!sealed || state.accountStatus.recording_delete_available === true) {
      const action = deleting ? '重试清理' : pending ? '取消上传' : '删除';
      actions.append(recordingButton(action, async () => {
        if (state.account?.user_id !== userID) throw new Error('录音账号已变化');
        if (!confirm(`${action} ${label}？`)) return;
        const id = item.recording_id;
        const path = `/recordings/${id}${pending ? '/pending' : ''}`;
        if (sealed) {
          const crypto = window.FrontierMediaCrypto;
          if (!userID || !crypto?.withRecordingSession) throw new Error('录音删除暂不可用');
          const task = pending && state.recordingUpload?.userID === userID && state.recordingUpload.request.recording_id === id
            ? state.recordingUpload : null;
          if (task) {
            if (state.recordingUploadBusy) throw new Error('请等待当前录音操作完成');
            state.recordingUploadBusy = true;
            updateRecordingUploadControls();
          }
          try {
            stopRecordingPreview(id);
            crypto.forgetRecordingPlayback(id);
            await crypto.withRecordingSession(id, sessionID => {
              if (state.account?.user_id !== userID) throw new Error('录音账号已变化');
              return accountApi(path, {method: 'DELETE', credentials: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer',
                headers: {...karaokeHeaders(false), 'X-Fc-Recording-Session': sessionID}});
            });
            if (task && state.recordingUpload === task) {
              state.recordingUpload = null;
              await task.encrypted.cleanup();
            }
          } catch (error) {
            if (state.account?.user_id === userID) await loadRecordings().catch(() => {});
            throw error;
          } finally {
            if (task) {
              state.recordingUploadBusy = false;
              updateRecordingUploadControls();
            }
          }
        } else {
          await accountApi(path, {method: 'DELETE', headers: karaokeHeaders(false)});
          stopRecordingPreview(id);
        }
        await refreshAccount();
      }));
    }
    row.append(info, actions); accountElements.recordingList.append(row);
  }
  if (!data.items.length) accountElements.recordingList.textContent = '暂无已上传录音。';
}

function recordingUploadTarget(raw, origin, suffix) {
  if (raw !== `${origin}/api/v1/node/recording-selected-upload${suffix}`)
    throw new Error('录音上传地址无效');
  return raw;
}

async function sendRecordingOwnerRequest(target, capability, file) {
  const headers = {'X-Fc-Selected-Upload': capability};
  if (file) headers['Content-Type'] = 'application/octet-stream';
  const response = await fetch(target, {method: file ? 'PUT' : 'POST', headers, body: file,
    credentials: 'omit', mode: 'cors', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store'});
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    throw new Error('无法确认存储节点的录音上传结果');
  }
  const signed = await response.json().catch(() => null);
  if (!signed?.receipt || typeof signed.receipt !== 'object' || Array.isArray(signed.receipt)
      || typeof signed.signature !== 'string' || !signed.signature || signed.signature.length > 4096)
    throw new Error('无法确认存储节点的录音上传结果');
  return signed;
}

async function sendSealedRecording(task) {
  const authorize = () => {
    if (state.account?.user_id !== task.userID
        || !recordingDestinations().some(item => item.member_id === task.memberID && item.address === task.origin))
      throw new Error('录音账号或存储节点已变化，上传状态待核验');
  };
  authorize();
  const common = {credentials: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer'};
  const id = task.request.recording_id;
  const crypto = window.FrontierMediaCrypto;
  if (!crypto?.withRecordingSession) throw new Error('录音授权组件未就绪');
  const sendControl = (action, body) => crypto.withRecordingSession(id, sessionID => {
    authorize();
    return accountApi(`/recordings/${id}/${action}`, {...common, method: 'POST', body,
      headers: {...karaokeHeaders(body !== undefined), 'X-Fc-Recording-Session': sessionID}});
  });
  const recovering = task.ticketRequested;
  task.ticketRequested = true;
  setStatus(recovering ? '正在核对本次录音的上传结果…' : '正在预留个人空间…');
  let ticket;
  try {
    ticket = recovering
      ? await sendControl('audio-recover')
      : await accountApi('/recordings/ticket', {...common, method: 'POST', headers: karaokeHeaders(), body: JSON.stringify(task.request)});
  } catch (error) {
    // The initial ticket's 413 is a size/quota refusal before reservation.
    // An uncertain response must still retain the exact encrypted task.
    if (!recovering && error.status === 413 && state.recordingUpload === task) {
      state.recordingUpload = null;
      await task.encrypted.cleanup();
    }
    throw error;
  }
  if (ticket?.recording_id !== id || ticket.storage_member_id !== task.memberID || ticket.transport !== 'Direct')
    throw new Error('录音预留与所选节点不一致');
  authorize();
  if (!recovering || ticket.state !== 'ready') {
    if (ticket.state !== 'pending' || typeof ticket.capability !== 'string' || ticket.capability.length > 4096
        || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(ticket.capability))
      throw new Error('录音上传授权无效');
    const target = recordingUploadTarget(ticket.url, task.origin, recovering ? '/recover' : '');
    const retryTarget = recovering && ticket.retry_upload_url !== undefined
      ? recordingUploadTarget(ticket.retry_upload_url, task.origin, '') : null;
    if (!recovering) setStatus('正在上传加密录音…');
    let signed;
    try {
      signed = await sendRecordingOwnerRequest(target, ticket.capability, recovering ? undefined : task.encrypted.file);
    } catch (error) {
      if (!retryTarget) throw error;
      authorize();
      setStatus('正在向原存储节点重传加密录音…');
      try {
        signed = await sendRecordingOwnerRequest(retryTarget, ticket.capability, task.encrypted.file);
      } catch (_) {
        task.recoveryMessage = '原存储节点未能确认或接收录音。请在个人主页取消这条待确认录音，再重新录制或选择原文件上传。';
        throw new Error(task.recoveryMessage);
      }
    }
    const result = await sendControl('audio-complete', JSON.stringify({receipt: signed.receipt, signature: signed.signature}));
    if (result.recording_id !== id || result.status !== 'ready') throw new Error('录音上传状态待核验');
  }
  if (state.recordingUpload === task) state.recordingUpload = null;
  await task.encrypted.cleanup();
  elements.previewHint.textContent = `已上传：${task.request.title}`;
  setStatus('录音已上传到个人空间。');
  await refreshAccount();
}

async function uploadSealedRecording(blob, title, media) {
  if (state.recordingUploadBusy || state.recordingUpload) throw new Error('请先完成当前录音上传');
  const memberID = accountElements.bindStorage.value;
  const userID = state.account?.user_id;
  const destination = recordingDestinations().find(item => item.member_id === memberID);
  if (!userID || !destination) throw new Error('请选择可用的录音存储节点');
  if (!window.FrontierMediaCrypto?.encryptRecordingAudio || typeof uploadSHA256 !== 'function') throw new Error('录音加密组件未就绪');
  const snapshot = state.recordingSnapshot;
  if (media && (snapshot?.encrypted ?? state.sourceLyricsEncrypted)) {
    if (!snapshot?.encrypted || snapshot.media !== media) throw new Error('录音歌词快照缺失，请重新录音');
    title = snapshot.title;
    blob = appendRecordingFooter(blob, {version: 1, title: recordingTitle(title), lyrics: snapshot.lyrics});
  }
  state.recordingUploadBusy = true;
  updateRecordingUploadControls();
  let encrypted, task, sessionID;
  try {
    setStatus('正在加密录音…');
    encrypted = await window.FrontierMediaCrypto.encryptRecordingAudio(blob, fields => {
      sessionID = fields.session_id;
      return accountApi('/recordings/crypto/audio-prepare', {method: 'POST', headers: karaokeHeaders(),
        credentials: 'same-origin', redirect: 'error', referrerPolicy: 'no-referrer', body: JSON.stringify(fields)});
    });
    if (!/^[a-f0-9]{32}$/.test(sessionID || '') || !/^[a-f0-9]{32}$/.test(encrypted.recording_id || ''))
      throw new Error('录音加密准备无效');
    const digest = await uploadSHA256(encrypted.file);
    if (state.account?.user_id !== userID) throw new Error('录音账号已变化，请重新登录');
    task = {userID, memberID, origin: destination.address, encrypted, ticketRequested: false, request: {
      recording_id: encrypted.recording_id, storage_member_id: memberID, cipher_sha256: digest,
      content_type: blob.type || 'application/octet-stream', title: recordingTitle(title), session_id: sessionID,
      encryption: encrypted.encryption, preparation_token: encrypted.preparation_token,
    }};
    state.recordingUpload = task;
    await sendSealedRecording(task);
  } finally {
    if (!task) await encrypted?.cleanup();
    state.recordingUploadBusy = false;
    updateRecordingUploadControls();
  }
}

async function uploadBlob(blob, title, media = null) {
  if (!state.account) throw new Error('请先登录 卡拉OK账号');
  if (sealedRecordingUpload()) return uploadSealedRecording(blob, title, media);
  let lyricSnapshot;
  let encryptedSnapshot;
  if (media && state.sourceLyricsEncrypted) {
    const snapshot = state.recordingSnapshot;
    if (!snapshot?.encrypted || snapshot.media !== media)
      throw new Error('加密来源录音歌词快照缺失，请重新录音');
    encryptedSnapshot = await window.FrontierMediaCrypto.encryptRecordingLyrics(snapshot.lyrics,
      fields => accountApi('/recordings/crypto/prepare', {method: 'POST', headers: karaokeHeaders(),
        body: JSON.stringify({media, ...fields})}));
    blob = await addRecordingMetadata(blob, snapshot, encryptedSnapshot.encrypted_lyrics);
    title = recordingTitle(snapshot.title);
  } else if (media) {
    lyricSnapshot = state.recordingSnapshot?.lyrics || state.lyrics;
    if (!Array.isArray(lyricSnapshot) || lyricSnapshot.length > 10000
      || lyricSnapshot.some(entry => !Number.isFinite(entry?.time) || entry.time < 0
        || typeof entry.text !== 'string' || new TextEncoder().encode(entry.text).byteLength > 4096)
      || new TextEncoder().encode(JSON.stringify(lyricSnapshot)).byteLength > 2 * 1024 * 1024) {
      throw new Error('录音歌词快照超过 10,000 行或 2 MiB 限制');
    }
  }
  setStatus('正在预留个人空间…');
  const ticket = await accountApi('/recordings/ticket', {method: 'POST', headers: karaokeHeaders(), body: JSON.stringify({
    size_bytes: blob.size, content_type: blob.type || 'application/octet-stream', media, title,
    ...(encryptedSnapshot ? {...encryptedSnapshot, lyrics: []} : media ? {lyrics: lyricSnapshot} : {}),
  })});
  const headers = {'Content-Type': blob.type || 'application/octet-stream'};
  if (ticket.direct) headers['X-Recording-Capability'] = ticket.capability;
  else Object.assign(headers, karaokeHeaders(false));
  setStatus(`正在${ticket.direct ? '直传' : '中继上传'}到录音存储节点…`);
  try {
    const uploaded = await fetch(ticket.upload_url, {method: 'PUT', headers, body: blob});
    if (!uploaded.ok) throw new Error(`录音上传失败（HTTP ${uploaded.status}）`);
    await accountApi(`/recordings/${ticket.recording_id}/finalize`, {method: 'POST', headers: karaokeHeaders(false)});
  } catch (error) {
    await accountApi(`/recordings/${ticket.recording_id}/pending`, {method: 'DELETE', headers: karaokeHeaders(false)}).catch(() => {});
    throw error;
  }
  elements.previewHint.textContent = `已上传：${ticket.filename}`;
  setStatus('录音已上传到个人空间。');
  await refreshAccount();
}

elements.upload.addEventListener('click', () => {
  if (!state.recordedBlob) return;
  const media = new URLSearchParams(location.search).get('media');
  uploadBlob(state.recordedBlob, state.context?.title, media).catch(error => setStatus(errorText(error), true));
});
elements.account.addEventListener('click', async () => {
  accountElements.accountModal.hidden = false;
  if (state.account) await loadRecordings();
});
accountElements.accountClose.onclick = () => { accountElements.accountModal.hidden = true; };
accountElements.showLogin.onclick = () => setAuthMode('login');
accountElements.showRegister.onclick = () => setAuthMode('register');
accountElements.captchaRefresh.onclick = loadCaptcha;
accountElements.authForm.onsubmit = async event => {
  event.preventDefault(); accountElements.authMessage.textContent = '处理中…';
  const payload = {
    username: accountElements.authUsername.value, password: accountElements.authPassword.value,
    challenge: accountElements.captchaImage.dataset.challenge || null,
    captcha: accountElements.captchaValue.value || null,
    webrtc_addresses: window.frontierCloudObservedAddresses || [],
  };
  try {
    await accountApi(`/${state.authMode}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
    await refreshAccount(); accountElements.authMessage.textContent = ''; setStatus('卡拉OK账号已登录。');
  } catch (error) {
    accountElements.authMessage.textContent = errorText(error);
    if (state.authMode === 'register' || error.captchaRequired) showCaptcha(true);
  }
};
accountElements.uploadFile.onclick = () => accountElements.uploadFileInput.click();
accountElements.bindStorage.onchange = updateRecordingUploadControls;
accountElements.retryRecordingUpload.onclick = async () => {
  if (state.recordingUploadBusy || !state.recordingUpload) return;
  state.recordingUploadBusy = true;
  updateRecordingUploadControls();
  try { await sendSealedRecording(state.recordingUpload); }
  catch (error) { setStatus(errorText(error), true); }
  finally { state.recordingUploadBusy = false; updateRecordingUploadControls(); }
};
accountElements.uploadFileInput.onchange = async event => {
  const file = event.target.files[0]; if (!file) return;
  try { await uploadBlob(file, file.name.replace(/\.[^.]+$/, ''), null); }
  catch (error) { setStatus(errorText(error), true); }
  finally { event.target.value = ''; }
};
accountElements.logoutAccount.onclick = async () => {
  await accountApi('/logout', {method: 'POST', headers: karaokeHeaders(false)}); state.account = null; await refreshAccount();
};
accountElements.passwordForm.onsubmit = async event => {
  event.preventDefault();
  await accountApi('/password', {method: 'POST', headers: karaokeHeaders(), body: JSON.stringify({current_password: accountElements.currentPassword.value, new_password: accountElements.newPassword.value})});
  state.account = null; accountElements.accountModal.hidden = true; await refreshAccount(); setStatus('密码已修改，请重新登录。');
};
accountElements.deleteAccount.onclick = async () => {
  const message = sealedRecordingUpload() ? '确认注销账号？请先清理个人主页中的录音和待确认上传。' : '注销账号会永久删除全部录音，确定继续？';
  if (!confirm(message)) return;
  accountElements.deleteAccount.disabled = true;
  try {
    const result = await accountApi('', {method: 'DELETE', headers: karaokeHeaders(false)});
    state.account = null;
    accountElements.accountModal.hidden = true;
    await refreshAccount();
    setStatus(result.status === 'deleted' ? '账号已注销。' : '账号正在注销。');
  } catch (error) {
    accountElements.recordingStorageStatus.textContent = errorText(error);
    setStatus(errorText(error), true);
  } finally {
    accountElements.deleteAccount.disabled = false;
  }
};

window.addEventListener('pagehide', () => {
  if (state.recorder && state.recorder.state !== 'inactive') state.recorder.stop();
  stopMicrophone();
  clearPreview();
  state.audioContext?.close();
});

requestAnimationFrame(lyricClock);
initialize().then(() => {
  state.ready = true;
  elements.record.disabled = false;
  void loadOptionalLyrics();
}).catch(error => {
  state.ready = false;
  setStatus(`卡拉OK页面初始化失败：${errorText(error)}`, true);
  elements.record.disabled = true;
});
refreshAccount().catch(error => {
  renderAccount();
  accountElements.authMessage.textContent = errorText(error);
});
setAuthMode('login');
