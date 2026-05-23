/**
 * Safe localStorage wrapper with error handling and versioning
 * Handles SSR, quota exceeded, and disabled localStorage gracefully
 */

const STORAGE_VERSION = 1;
const VERSION_KEY = '__storage_version__';

interface StorageOptions {
  version?: number;
  ttl?: number; // Time to live in milliseconds
}

class StorageManager {
  private isAvailable: boolean;

  constructor() {
    this.isAvailable = this.checkAvailability();
  }

  private checkAvailability(): boolean {
    try {
      if (typeof window === 'undefined') return false;
      const test = '__storage_test__';
      localStorage.setItem(test, test);
      localStorage.removeItem(test);
      return true;
    } catch (error) {
      console.warn('localStorage is not available:', error);
      return false;
    }
  }

  /**
   * Get a value from localStorage
   */
  get<T = unknown>(key: string, defaultValue?: T, options?: StorageOptions): T | null {
    try {
      if (!this.isAvailable) return defaultValue ?? null;

      const item = localStorage.getItem(key);
      if (!item) return defaultValue ?? null;

      const parsed = JSON.parse(item);

      // Check TTL
      if (options?.ttl && parsed.timestamp) {
        const age = Date.now() - parsed.timestamp;
        if (age > options.ttl) {
          this.remove(key);
          return defaultValue ?? null;
        }
      }

      return parsed.value ?? (defaultValue ?? null);
    } catch (error) {
      console.error(`Failed to get storage key "${key}":`, error);
      return defaultValue ?? null;
    }
  }

  /**
   * Set a value in localStorage
   */
  set(key: string, value: unknown, options?: StorageOptions): boolean {
    try {
      if (!this.isAvailable) return false;

      const data = {
        value,
        timestamp: Date.now(),
        version: options?.version ?? STORAGE_VERSION,
      };

      localStorage.setItem(key, JSON.stringify(data));
      return true;
    } catch (error) {
      if (error instanceof Error && error.name === 'QuotaExceededError') {
        console.error('localStorage quota exceeded:', error);
      } else {
        console.error(`Failed to set storage key "${key}":`, error);
      }
      return false;
    }
  }

  /**
   * Remove a value from localStorage
   */
  remove(key: string): boolean {
    try {
      if (!this.isAvailable) return false;
      localStorage.removeItem(key);
      return true;
    } catch (error) {
      console.error(`Failed to remove storage key "${key}":`, error);
      return false;
    }
  }

  /**
   * Clear all localStorage
   */
  clear(): boolean {
    try {
      if (!this.isAvailable) return false;
      localStorage.clear();
      return true;
    } catch (error) {
      console.error('Failed to clear storage:', error);
      return false;
    }
  }

  /**
   * Check if a key exists
   */
  has(key: string): boolean {
    try {
      if (!this.isAvailable) return false;
      return localStorage.getItem(key) !== null;
    } catch (error) {
      console.error(`Failed to check storage key "${key}":`, error);
      return false;
    }
  }

  /**
   * Get all keys
   */
  keys(): string[] {
    try {
      if (!this.isAvailable) return [];
      return Object.keys(localStorage);
    } catch (error) {
      console.error('Failed to get storage keys:', error);
      return [];
    }
  }

  /**
   * Get storage size in bytes
   */
  getSize(): number {
    try {
      if (!this.isAvailable) return 0;
      let size = 0;
      for (let key in localStorage) {
        if (localStorage.hasOwnProperty(key)) {
          size += localStorage[key].length + key.length;
        }
      }
      return size;
    } catch (error) {
      console.error('Failed to get storage size:', error);
      return 0;
    }
  }
}

// Export singleton instance
export const storage = new StorageManager();

// Export type for options
export type { StorageOptions };
