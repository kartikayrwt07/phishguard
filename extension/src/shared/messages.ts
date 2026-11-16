/**
 * Strongly typed message protocol for PhishGuard Chrome Extension.
 * Handles communication between Background Service Worker, Content Scripts, Popup, and Options.
 */

import {
  DOMSignals,
  UserSettings,
} from './types';

export type {
  AllowlistEntry,
  DeviceInfo,
  DOMSignals,
  ScanResult,
  UserSettings,
} from './types';

export type ExtensionMessageType =
  | 'PING'
  | 'ANALYZE_URL'
  | 'SUBMIT_DOM_SIGNALS'
  | 'GET_SETTINGS'
  | 'UPDATE_SETTINGS'
  | 'GET_SCAN_CACHE'
  | 'ADD_ALLOWLIST'
  | 'REMOVE_ALLOWLIST'
  | 'GET_ALLOWLIST'
  | 'GET_DEVICE_INFO';

export interface PingMessage {
  type: 'PING';
}

export interface AnalyzeUrlMessage {
  type: 'ANALYZE_URL';
  payload: {
    url: string;
    tabId?: number;
    forceEnrichment?: boolean;
  };
}

export interface SubmitDomSignalsMessage {
  type: 'SUBMIT_DOM_SIGNALS';
  payload: {
    url: string;
    signals: DOMSignals;
    tabId?: number;
  };
}

export interface GetSettingsMessage {
  type: 'GET_SETTINGS';
}

export interface UpdateSettingsMessage {
  type: 'UPDATE_SETTINGS';
  payload: Partial<UserSettings>;
}

export interface GetScanCacheMessage {
  type: 'GET_SCAN_CACHE';
  payload: {
    url: string;
  };
}

export interface AddAllowlistMessage {
  type: 'ADD_ALLOWLIST';
  payload: {
    domain: string;
    reason?: string;
  };
}

export interface RemoveAllowlistMessage {
  type: 'REMOVE_ALLOWLIST';
  payload: {
    domain: string;
  };
}

export interface GetAllowlistMessage {
  type: 'GET_ALLOWLIST';
}

export interface GetDeviceInfoMessage {
  type: 'GET_DEVICE_INFO';
}

export type ExtensionMessage =
  | PingMessage
  | AnalyzeUrlMessage
  | SubmitDomSignalsMessage
  | GetSettingsMessage
  | UpdateSettingsMessage
  | GetScanCacheMessage
  | AddAllowlistMessage
  | RemoveAllowlistMessage
  | GetAllowlistMessage
  | GetDeviceInfoMessage;

export interface MessageResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

/**
 * Type-safe dispatcher for sending messages to the background service worker.
 */
export async function sendMessageToBackground<T>(
  message: ExtensionMessage
): Promise<MessageResponse<T>> {
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
    return {
      success: false,
      error: 'Chrome runtime messaging is unavailable in this environment',
    };
  }

  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (response: MessageResponse<T>) => {
        const lastError = chrome.runtime.lastError;
        if (lastError) {
          resolve({
            success: false,
            error: lastError.message || 'Unknown runtime error occurred',
          });
          return;
        }

        if (!response) {
          resolve({
            success: false,
            error: 'No response received from background service worker',
          });
          return;
        }

        resolve(response);
      });
    } catch (err) {
      resolve({
        success: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });
}
