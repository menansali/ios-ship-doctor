/**
 * Apple App Store review knowledge base.
 *
 * These are the rules the review team enforces automatically at upload/processing
 * time. Getting any of them wrong produces the classic "Invalid Binary" email or
 * a Resolution Center rejection. Ship Doctor's whole job is to check them BEFORE
 * you hit Submit.
 *
 * Sources: Apple "Describing use of required reason API" + "Privacy manifest files"
 * documentation. Category identifiers and default reason codes below are Apple's.
 */

/** A required-reason API category and the code patterns that imply you use it. */
export interface RequiredReasonCategory {
  /** Apple's NSPrivacyAccessedAPIType value. */
  category: string;
  /** Human label. */
  label: string;
  /**
   * Symbols / substrings whose presence in source implies use of this category.
   * Matched case-sensitively against source text (word-ish boundaries applied
   * by the scanner).
   */
  signatures: string[];
  /** The most common valid reason code, used when auto-generating a manifest. */
  defaultReason: string;
  /** All valid reason codes Apple accepts for this category (for validation). */
  validReasons: string[];
}

export const REQUIRED_REASON_CATEGORIES: RequiredReasonCategory[] = [
  {
    category: "NSPrivacyAccessedAPICategoryFileTimestamp",
    label: "File timestamp APIs",
    signatures: [
      "creationDate",
      "modificationDate",
      "contentModificationDateKey",
      "creationDateKey",
      "getattrlist",
      "getattrlistbulk",
      "fgetattrlist",
      "stat",
      "fstat",
      "lstat",
      "NSFileCreationDate",
      "NSFileModificationDate",
    ],
    defaultReason: "C617.1",
    validReasons: ["DDA9.1", "C617.1", "3B52.1", "0A2A.1"],
  },
  {
    category: "NSPrivacyAccessedAPICategorySystemBootTime",
    label: "System boot time APIs",
    signatures: [
      "systemUptime",
      "mach_absolute_time",
      "mach_continuous_time",
      "clock_gettime",
    ],
    defaultReason: "35F9.1",
    validReasons: ["35F9.1", "8FFB.1", "3D61.1"],
  },
  {
    category: "NSPrivacyAccessedAPICategoryDiskSpace",
    label: "Disk space APIs",
    signatures: [
      "volumeAvailableCapacity",
      "volumeAvailableCapacityForImportantUsageKey",
      "volumeAvailableCapacityForOpportunisticUsageKey",
      "volumeTotalCapacityKey",
      "systemFreeSize",
      "systemSize",
      "NSFileSystemFreeSize",
      "NSFileSystemSize",
      "statfs",
      "statvfs",
      "fstatfs",
    ],
    defaultReason: "E174.1",
    validReasons: ["85F4.1", "E174.1", "7D9E.1", "B728.1"],
  },
  {
    category: "NSPrivacyAccessedAPICategoryActiveKeyboards",
    label: "Active keyboard APIs",
    signatures: ["activeInputModes"],
    defaultReason: "3EC4.1",
    validReasons: ["3EC4.1", "54BD.1"],
  },
  {
    category: "NSPrivacyAccessedAPICategoryUserDefaults",
    label: "User defaults APIs",
    signatures: ["UserDefaults", "NSUserDefaults"],
    defaultReason: "CA92.1",
    validReasons: ["CA92.1", "1C8F.1", "C56D.1", "AC6B.1"],
  },
];

/**
 * Permission-gated capabilities. If the code/dependencies use the API on the
 * left, Apple REQUIRES the Info.plist usage-description key on the right, or the
 * app crashes on first use / is rejected.
 */
export interface UsageDescriptionRule {
  /** Info.plist key that must be present with a non-empty purpose string. */
  key: string;
  label: string;
  /** Substrings in source/pods that imply this permission is used. */
  signatures: string[];
}

export const USAGE_DESCRIPTION_RULES: UsageDescriptionRule[] = [
  {
    key: "NSCameraUsageDescription",
    label: "Camera",
    signatures: ["AVCaptureDevice", "UIImagePickerControllerSourceTypeCamera", "react-native-vision-camera", "expo-camera", "captureDevice"],
  },
  {
    key: "NSPhotoLibraryUsageDescription",
    label: "Photo Library (read)",
    signatures: ["PHPhotoLibrary", "UIImagePickerController", "PHAsset", "react-native-image-picker", "expo-image-picker", "photo library"],
  },
  {
    key: "NSPhotoLibraryAddUsageDescription",
    label: "Photo Library (add/save)",
    signatures: ["UIImageWriteToSavedPhotosAlbum", "PHAssetChangeRequest", "saveToCameraRoll"],
  },
  {
    key: "NSMicrophoneUsageDescription",
    label: "Microphone",
    signatures: ["AVAudioRecorder", "AVAudioSession", "requestRecordPermission", "microphone"],
  },
  {
    key: "NSLocationWhenInUseUsageDescription",
    label: "Location (when in use)",
    signatures: ["CLLocationManager", "requestWhenInUseAuthorization", "react-native-geolocation", "expo-location"],
  },
  {
    key: "NSLocationAlwaysAndWhenInUseUsageDescription",
    label: "Location (always)",
    signatures: ["requestAlwaysAuthorization", "allowsBackgroundLocationUpdates"],
  },
  {
    key: "NSContactsUsageDescription",
    label: "Contacts",
    signatures: ["CNContactStore", "react-native-contacts", "expo-contacts", "ABAddressBook"],
  },
  {
    key: "NSCalendarsUsageDescription",
    label: "Calendars",
    signatures: ["EKEventStore", "react-native-calendar-events", "expo-calendar"],
  },
  {
    key: "NSFaceIDUsageDescription",
    label: "Face ID",
    signatures: ["LAContext", "LAPolicyDeviceOwnerAuthenticationWithBiometrics", "react-native-biometrics", "expo-local-authentication"],
  },
  {
    key: "NSUserTrackingUsageDescription",
    label: "App Tracking Transparency",
    signatures: ["ATTrackingManager", "requestTrackingAuthorization", "AppTrackingTransparency", "idfa", "advertisingIdentifier"],
  },
  {
    key: "NSBluetoothAlwaysUsageDescription",
    label: "Bluetooth",
    signatures: ["CBCentralManager", "CBPeripheralManager", "CoreBluetooth"],
  },
  {
    key: "NSMotionUsageDescription",
    label: "Motion & Fitness",
    signatures: ["CMMotionManager", "CMPedometer", "CoreMotion"],
  },
];

/**
 * Known "you shipped a placeholder / test credential" traps that fail review.
 */
export interface CredentialTrap {
  id: string;
  label: string;
  /** File to look in, relative to the app source root, plus the bad value. */
  plistKey?: string;
  badValues: string[];
  advice: string;
}

export const CREDENTIAL_TRAPS: CredentialTrap[] = [
  {
    id: "admob-test-app-id",
    label: "Google AdMob TEST application ID in Info.plist",
    plistKey: "GADApplicationIdentifier",
    // Google's public sample IDs — must never ship to production.
    badValues: ["ca-app-pub-3940256099942544"],
    advice:
      "This is Google's public sample AdMob App ID. Replace GADApplicationIdentifier with your real ca-app-pub-… ID from the AdMob console before submitting, or ads won't serve and review may flag it.",
  },
];

/** Reason-code metadata for FileTimestamp, used in generated-manifest comments. */
export const REASON_HINTS: Record<string, string> = {
  "C617.1": "Access timestamps of files inside the app container / group container / CloudKit.",
  "DDA9.1": "Access timestamps of files displayed to the user (e.g. a file browser).",
  "35F9.1": "Measure elapsed time using system uptime for in-app operations.",
  "CA92.1": "Read/write UserDefaults for values accessible only to this app.",
  "E174.1": "Check available disk space to write files needed by the app.",
};
