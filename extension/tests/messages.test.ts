import { describe, it, expect, beforeEach } from 'vitest';
import { handleMessage } from '../src/background/index';
import { storageManager } from '../src/shared/storage';
import {
  AddAllowlistMessage,
  AnalyzeUrlMessage,
  GetAllowlistMessage,
  GetDeviceInfoMessage,
  GetSettingsMessage,
  PingMessage,
  RemoveAllowlistMessage,
  UpdateSettingsMessage,
} from '../src/shared/messages';
import { DeviceInfo, UserSettings } from '../src/shared/types';

describe('Service Worker Message Bus', () => {
  const dummySender = {
    id: 'test-extension-id',
    tab: { id: 1 } as chrome.tabs.Tab,
  } as chrome.runtime.MessageSender;

  beforeEach(async () => {
    await storageManager.clearAll();
  });

  it('responds to PING message with PONG and timestamp', async () => {
    const pingMsg: PingMessage = { type: 'PING' };
    const resp = await handleMessage(pingMsg, dummySender);

    expect(resp.success).toBe(true);
    expect((resp.data as { type: string }).type).toBe('PONG');
    expect(typeof (resp.data as { timestamp: number }).timestamp).toBe('number');
  });

  it('handles GET_DEVICE_INFO returning valid installation metadata', async () => {
    const msg: GetDeviceInfoMessage = { type: 'GET_DEVICE_INFO' };
    const resp = await handleMessage(msg, dummySender);

    expect(resp.success).toBe(true);
    const data = resp.data as DeviceInfo;
    expect(data.deviceId).toBeDefined();
    expect(data.extensionVersion).toBe('1.0.0');
  });

  it('handles GET_SETTINGS and UPDATE_SETTINGS messages', async () => {
    const getMsg: GetSettingsMessage = { type: 'GET_SETTINGS' };
    let resp = await handleMessage(getMsg, dummySender);
    expect(resp.success).toBe(true);
    let settings = resp.data as UserSettings;
    expect(settings.sensitivityThreshold).toBe(50);

    const updateMsg: UpdateSettingsMessage = {
      type: 'UPDATE_SETTINGS',
      payload: { sensitivityThreshold: 80 },
    };
    resp = await handleMessage(updateMsg, dummySender);
    expect(resp.success).toBe(true);
    settings = resp.data as UserSettings;
    expect(settings.sensitivityThreshold).toBe(80);
  });

  it('handles ADD_ALLOWLIST, GET_ALLOWLIST, and REMOVE_ALLOWLIST messages', async () => {
    const addMsg: AddAllowlistMessage = {
      type: 'ADD_ALLOWLIST',
      payload: { domain: 'trusted.org', reason: 'Internal tool' },
    };
    let resp = await handleMessage(addMsg, dummySender);
    expect(resp.success).toBe(true);

    const getMsg: GetAllowlistMessage = { type: 'GET_ALLOWLIST' };
    resp = await handleMessage(getMsg, dummySender);
    expect(resp.success).toBe(true);
    expect((resp.data as any[]).length).toBe(1);
    expect((resp.data as any[])[0].domain).toBe('trusted.org');

    const removeMsg: RemoveAllowlistMessage = {
      type: 'REMOVE_ALLOWLIST',
      payload: { domain: 'trusted.org' },
    };
    resp = await handleMessage(removeMsg, dummySender);
    expect(resp.success).toBe(true);

    resp = await handleMessage(getMsg, dummySender);
    expect((resp.data as any[]).length).toBe(0);
  });

  it('handles ANALYZE_URL with allowlist override', async () => {
    await storageManager.addAllowlistDomain('google.com');

    const analyzeMsg: AnalyzeUrlMessage = {
      type: 'ANALYZE_URL',
      payload: { url: 'https://mail.google.com/mail/u/0' },
    };

    const resp = await handleMessage(analyzeMsg, dummySender);
    expect(resp.success).toBe(true);
    const result = resp.data as any;
    expect(result.verdict).toBe('SAFE');
    expect(result.score).toBe(0);
    expect(result.source).toBe('override');
    expect(result.evidence[0].rule_name).toBe('USER_ALLOWLIST');
  });

  it('rejects unsupported message types gracefully', async () => {
    const invalidMsg = { type: 'NON_EXISTENT_ACTION' } as any;
    const resp = await handleMessage(invalidMsg, dummySender);

    expect(resp.success).toBe(false);
    expect(resp.error).toContain('Unrecognized message type');
  });
});

