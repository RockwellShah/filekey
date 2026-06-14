// FileKey reference web app.
// UI/flow is a faithful reproduction of filekey v1 (source.txt): typewriter chat
// (char_speed = characters per animation frame), the filekey "dp" badge on each
// message, two-step auth (generate -> "Now tap to unlock"), animated
// Encrypting/Decrypting status, upload-right / download-left cards with Share+Save,
// the hamburger ("chiz") menu with v1's verbatim content panels.
//
// FILE SEMANTICS follow the new spec (user-confirmed), NOT v1:
//   - route lock/unlock by the FKEY magic header, not the filename extension
//   - shared files are named ".shared.filekey" (spec §10), not ".shared_filekey"
//   - Save uses the native save picker where available
// Other spec deltas are marked  // SPEC-DELTA.
import {
  Namespace, NamespaceSet,
  deriveIdentityFromPrf, masterPrkFromPrfSecret,
  encodeShareKey, decodeShareKey, identityFingerprint,
  encodeRecoveryBip39,
  encryptToSelf, decrypt, encryptStream, decryptStream,
  parseHeader, FileKeyError, HEADER_LEN,
  type Identity, type Metadata, type ByteSource,
} from "../src/index.js";
import { checkSupport, enrollPasskey, getPrfSecret, prfBrowserSupport, deploymentRpId } from "./webauthn.js";
import * as Contacts from "./contacts.js";
import { collectFromInput, collectFromDrop, zipBundleToBlob, bundleName, type BundleItem } from "./bundle.js";
import qrcode from "qrcode-generator"; // tiny, dependency-free QR encoder — bundled offline (no CDN; see send-me-a-file spec §8)
import versionManifest from "./version.json"; // user-facing version + release notes; re-fetched at runtime to surface a newer deploy

// ---- v1 icons (verbatim SVG paths from source.txt) ----
const SVG = {
  logo: `<svg viewBox="0 0 22 27"><path d="M21.9873 8.81596C21.9827 8.75523 21.9678 8.69679 21.9506 8.63607C21.9334 8.57648 21.9174 8.51919 21.8899 8.46419C21.8807 8.44471 21.8796 8.42409 21.8693 8.40461C19.9924 5.27768 17.349 2.63298 14.2221 0.757408C14.2037 0.74595 14.182 0.74595 14.1625 0.735638C14.1086 0.708138 14.0525 0.692095 13.9929 0.674909C13.931 0.657721 13.8715 0.64168 13.8084 0.638242C13.7878 0.638242 13.7706 0.62793 13.75 0.62793H5.5C2.46693 0.62793 0 3.09492 0 6.12793V20.7946C0 23.8277 2.46699 26.2946 5.5 26.2946H16.5C19.5331 26.2946 22 23.8276 22 20.7946V8.87793C22 8.85616 21.9896 8.83773 21.9873 8.81596ZM19.3748 7.96116H18.3332C16.312 7.96116 14.6666 6.31573 14.6666 4.29449V3.25292C16.4793 4.55459 18.073 6.14839 19.3748 7.96116ZM16.4999 24.4612H5.49992C3.47867 24.4612 1.83325 22.8157 1.83325 20.7945V6.12783C1.83325 4.10658 3.47867 2.46116 5.49992 2.46116H12.8332V4.29449C12.8332 7.32756 15.3002 9.79449 18.3332 9.79449H20.1666V20.7945C20.1666 22.8157 18.5212 24.4612 16.4999 24.4612ZM14.6666 14.5462V12.5444C14.6666 10.5232 13.0212 8.87777 10.9999 8.87777C8.97867 8.87777 7.33325 10.5232 7.33325 12.5444V14.5462C6.26877 14.9266 5.49992 15.9338 5.49992 17.1278V19.8778C5.49992 21.3937 6.73397 22.6278 8.24992 22.6278H13.7499C15.2659 22.6278 16.4999 21.3937 16.4999 19.8778V17.1278C16.4999 15.9338 15.7311 14.9266 14.6666 14.5462ZM9.16658 12.5444C9.16658 11.5338 9.98929 10.7111 10.9999 10.7111C12.0105 10.7111 12.8332 11.5338 12.8332 12.5444V14.3778H9.16658V12.5444ZM14.6666 19.8778C14.6666 20.3831 14.2552 20.7944 13.7499 20.7944H8.24992C7.74459 20.7944 7.33325 20.3831 7.33325 19.8778V17.1278C7.33325 16.6224 7.74459 16.2111 8.24992 16.2111H13.7499C14.2552 16.2111 14.6666 16.6224 14.6666 17.1278V19.8778Z"/></svg>`,
  filekey: `<svg viewBox="0 0 13 16"><path d="M10.4867 6.88902V4.77531C10.4867 2.64104 8.7493 0.903607 6.61503 0.903607C4.48076 0.903607 2.74332 2.64104 2.74332 4.77531V6.88902C1.61932 7.29072 0.807471 8.35423 0.807471 9.61495V12.5187C0.807471 14.1194 2.11053 15.4225 3.71125 15.4225H9.51881C11.1195 15.4225 12.4226 14.1194 12.4226 12.5187V9.61495C12.4226 8.35423 11.6107 7.29072 10.4867 6.88902ZM4.67918 4.77531C4.67918 3.70818 5.5479 2.83946 6.61503 2.83946C7.68217 2.83946 8.55088 3.70818 8.55088 4.77531V6.71117H4.67918V4.77531ZM10.4867 12.5187C10.4867 13.0523 10.0524 13.4867 9.51881 13.4867H3.71125C3.17767 13.4867 2.74332 13.0523 2.74332 12.5187V9.61495C2.74332 9.08137 3.17767 8.64702 3.71125 8.64702H9.51881C10.0524 8.64702 10.4867 9.08137 10.4867 9.61495V12.5187Z"/></svg>`,
  file: `<svg viewBox="0 0 25 30"><path d="M24.9856 9.30458C24.9804 9.23557 24.9634 9.16916 24.9439 9.10015C24.9244 9.03245 24.9061 8.96734 24.8749 8.90484C24.8645 8.88271 24.8632 8.85927 24.8515 8.83714C22.7187 5.2838 19.7148 2.27847 16.1615 0.147133C16.1406 0.134112 16.1159 0.134113 16.0938 0.122395C16.0326 0.0911446 15.9688 0.0729129 15.901 0.0533829C15.8307 0.0338515 15.763 0.0156254 15.6914 0.0117188C15.668 0.0117188 15.6484 0 15.625 0H6.25C2.80333 0 0 2.8034 0 6.25V22.9167C0 26.3633 2.8034 29.1667 6.25 29.1667H18.75C22.1967 29.1667 25 26.3633 25 22.9167V9.375C25 9.35026 24.9882 9.32932 24.9856 9.30458ZM22.0168 8.33321H20.8332C18.5364 8.33321 16.6666 6.46342 16.6666 4.16655V2.98295C18.7265 4.46212 20.5375 6.27325 22.0168 8.33321ZM18.7499 27.0832H6.2499C3.95304 27.0832 2.08324 25.2134 2.08324 22.9165V6.24988C2.08324 3.95301 3.95304 2.08321 6.2499 2.08321H14.5832V4.16655C14.5832 7.61322 17.3866 10.4165 20.8332 10.4165H22.9166V22.9165C22.9166 25.2134 21.0468 27.0832 18.7499 27.0832Z"/><path d="M17.5457 16.1931C17.4066 16.0458 17.2306 15.9722 17.0178 15.9722H7.69971C7.47873 15.9722 7.29457 16.0458 7.14725 16.1931C6.99993 16.3323 6.92627 16.5083 6.92627 16.7211C6.92627 16.9339 6.99993 17.1139 7.14725 17.2612C7.29457 17.4086 7.47873 17.4822 7.69971 17.4822H17.0178C17.2306 17.4822 17.4066 17.4086 17.5457 17.2612C17.693 17.1139 17.7667 16.9339 17.7667 16.7211C17.7667 16.5083 17.693 16.3323 17.5457 16.1931Z"/><path d="M17.5457 20.4777C17.4066 20.3304 17.2306 20.2568 17.0178 20.2568H7.69971C7.47873 20.2568 7.29457 20.3304 7.14725 20.4777C6.99993 20.6251 6.92627 20.8092 6.92627 21.0302C6.92627 21.2348 6.99993 21.4108 7.14725 21.5581C7.29457 21.6972 7.47873 21.7668 7.69971 21.7668H17.0178C17.2306 21.7668 17.4066 21.6972 17.5457 21.5581C17.693 21.4108 17.7667 21.2348 17.7667 21.0302C17.7667 20.8092 17.693 20.6251 17.5457 20.4777Z"/></svg>`,
  plus: `<svg viewBox="0 0 34 33"><path d="M17 32.7086C14.7774 32.7086 12.6917 32.2873 10.7429 31.4446C8.79413 30.6124 7.08238 29.4589 5.60764 27.9842C4.1329 26.5095 2.97417 24.7977 2.13146 22.8489C1.29929 20.9002 0.883203 18.8145 0.883203 16.5918C0.883203 14.3692 1.29929 12.2835 2.13146 10.3347C2.97417 8.38596 4.1329 6.67421 5.60764 5.19947C7.08238 3.7142 8.79413 2.55547 10.7429 1.7233C12.6917 0.891126 14.7774 0.475039 17 0.475039C19.2226 0.475039 21.3083 0.891126 23.2571 1.7233C25.2059 2.55547 26.9176 3.7142 28.3924 5.19947C29.8671 6.67421 31.0206 8.38596 31.8527 10.3347C32.6954 12.2835 33.1168 14.3692 33.1168 16.5918C33.1168 18.8145 32.6954 20.9002 31.8527 22.8489C31.0206 24.7977 29.8671 26.5095 28.3924 27.9842C26.9176 29.4589 25.2059 30.6124 23.2571 31.4446C21.3083 32.2873 19.2226 32.7086 17 32.7086ZM17 30.0225C18.854 30.0225 20.592 29.6749 22.2143 28.9796C23.8365 28.2844 25.2638 27.3206 26.4963 26.0881C27.7287 24.8556 28.6926 23.4283 29.3878 21.8061C30.083 20.1839 30.4307 18.4458 30.4307 16.5918C30.4307 14.7379 30.083 12.9998 29.3878 11.3776C28.6926 9.74483 27.7287 8.31749 26.4963 7.09557C25.2638 5.86311 23.8365 4.89926 22.2143 4.20402C20.592 3.50879 18.854 3.16117 17 3.16117C15.146 3.16117 13.408 3.50879 11.7857 4.20402C10.1635 4.89926 8.73619 5.86311 7.50373 7.09557C6.27127 8.31749 5.30742 9.74483 4.61219 11.3776C3.91695 12.9998 3.56934 14.7379 3.56934 16.5918C3.56934 18.4458 3.91695 20.1839 4.61219 21.8061C5.30742 23.4283 6.27127 24.8556 7.50373 26.0881C8.73619 27.3206 10.1635 28.2844 11.7857 28.9796C13.408 29.6749 15.146 30.0225 17 30.0225ZM9.66844 16.5918C9.66844 16.1915 9.78958 15.8703 10.0319 15.628C10.2847 15.3752 10.6165 15.2488 11.0273 15.2488H15.6727V10.6033C15.6727 10.2031 15.7939 9.8765 16.0362 9.62369C16.2784 9.37088 16.5892 9.24447 16.9684 9.24447C17.3687 9.24447 17.69 9.37088 17.9322 9.62369C18.1851 9.86597 18.3115 10.1925 18.3115 10.6033V15.2488H22.9727C23.373 15.2488 23.6943 15.3752 23.9365 15.628C24.1894 15.8703 24.3158 16.1915 24.3158 16.5918C24.3158 16.9711 24.1894 17.2818 23.9365 17.5241C23.6943 17.7664 23.373 17.8875 22.9727 17.8875H18.3115V22.5487C18.3115 22.949 18.1851 23.2756 17.9322 23.5284C17.69 23.7707 17.3687 23.8918 16.9684 23.8918C16.5892 23.8918 16.2784 23.7707 16.0362 23.5284C15.7939 23.2756 15.6727 22.949 15.6727 22.5487V17.8875H11.0273C10.627 17.8875 10.3005 17.7664 10.0477 17.5241C9.79484 17.2818 9.66844 16.9711 9.66844 16.5918Z"/></svg>`,
  share: `<svg viewBox="0 0 15 19"><path d="M2.64062 18.3877C1.77604 18.3877 1.11719 18.1637 0.664062 17.7158C0.216146 17.2679 -0.0078125 16.6169 -0.0078125 15.7627V8.15332C-0.0078125 7.29395 0.216146 6.6429 0.664062 6.2002C1.11719 5.75228 1.77604 5.52832 2.64062 5.52832H4.86719V7.2627H2.78125C2.4375 7.2627 2.17448 7.35124 1.99219 7.52832C1.8151 7.7002 1.72656 7.96582 1.72656 8.3252V15.583C1.72656 15.9424 1.8151 16.208 1.99219 16.3799C2.17448 16.557 2.4375 16.6455 2.78125 16.6455H11.5078C11.8464 16.6455 12.1068 16.557 12.2891 16.3799C12.4714 16.208 12.5625 15.9424 12.5625 15.583V8.3252C12.5625 7.96582 12.4714 7.7002 12.2891 7.52832C12.1068 7.35124 11.8464 7.2627 11.5078 7.2627H9.42188V5.52832H11.6562C12.5208 5.52832 13.1771 5.75228 13.625 6.2002C14.0781 6.6429 14.3047 7.29395 14.3047 8.15332V15.7627C14.3047 16.6169 14.0781 17.2679 13.625 17.7158C13.1771 18.1637 12.5208 18.3877 11.6562 18.3877H2.64062ZM7.14062 11.958C6.92188 11.958 6.73438 11.8799 6.57812 11.7236C6.42188 11.5674 6.34375 11.3851 6.34375 11.1768V3.40332L6.41406 2.25488L6.02344 2.77832L4.97656 3.89551C4.83073 4.04655 4.65104 4.12207 4.4375 4.12207C4.25 4.12207 4.08594 4.05957 3.94531 3.93457C3.8099 3.80957 3.74219 3.64811 3.74219 3.4502C3.74219 3.2627 3.8151 3.09342 3.96094 2.94238L6.52344 0.481445C6.63281 0.377279 6.73698 0.306966 6.83594 0.270508C6.9349 0.228841 7.03646 0.208008 7.14062 0.208008C7.25 0.208008 7.35417 0.228841 7.45312 0.270508C7.55729 0.306966 7.66146 0.377279 7.76562 0.481445L10.3281 2.94238C10.474 3.09342 10.5469 3.2627 10.5469 3.4502C10.5469 3.64811 10.4766 3.80957 10.3359 3.93457C10.1953 4.05957 10.0312 4.12207 9.84375 4.12207C9.63021 4.12207 9.45312 4.04655 9.3125 3.89551L8.27344 2.77832L7.88281 2.25488L7.94531 3.40332V11.1768C7.94531 11.3851 7.86719 11.5674 7.71094 11.7236C7.5599 11.8799 7.36979 11.958 7.14062 11.958Z"/></svg>`,
  copy: `<svg viewBox="0 0 17 21"><path d="M3.85938 5.22363V3.31738C3.85938 2.47363 4.07292 1.83561 4.5 1.40332C4.92708 0.96582 5.5599 0.74707 6.39844 0.74707H9.33594C9.78906 0.74707 10.1927 0.812174 10.5469 0.942383C10.9062 1.06738 11.2318 1.28092 11.5234 1.58301L15.4141 5.54395C15.7214 5.86165 15.9375 6.2002 16.0625 6.55957C16.1875 6.91374 16.25 7.34863 16.25 7.86426V14.0518C16.25 14.8955 16.0339 15.5335 15.6016 15.9658C15.1745 16.3981 14.5443 16.6143 13.7109 16.6143H12.1094V15.083H13.5703C13.9505 15.083 14.2344 14.9867 14.4219 14.7939C14.6146 14.596 14.7109 14.3174 14.7109 13.958V7.48926H11.2734C10.7891 7.48926 10.4219 7.36686 10.1719 7.12207C9.92188 6.87207 9.79688 6.50488 9.79688 6.02051V2.28613H6.52344C6.14844 2.28613 5.86458 2.38249 5.67188 2.5752C5.48438 2.7679 5.39062 3.04655 5.39062 3.41113V5.22363H3.85938ZM11.0781 5.8252C11.0781 5.96061 11.1068 6.05957 11.1641 6.12207C11.2266 6.17936 11.3229 6.20801 11.4531 6.20801H14.3125L11.0781 2.92676V5.8252ZM-0.0078125 18.0596V7.3252C-0.0078125 6.48145 0.205729 5.84342 0.632812 5.41113C1.0599 4.97363 1.69271 4.75488 2.53125 4.75488H5.25C5.72396 4.75488 6.11458 4.80697 6.42188 4.91113C6.73438 5.01009 7.04688 5.22103 7.35938 5.54395L11.5938 9.84082C11.8125 10.0648 11.9792 10.2783 12.0938 10.4814C12.2083 10.6846 12.2839 10.9111 12.3203 11.1611C12.362 11.4059 12.3828 11.7028 12.3828 12.0518V18.0596C12.3828 18.9033 12.1693 19.5413 11.7422 19.9736C11.3151 20.4059 10.6823 20.6221 9.84375 20.6221H2.53125C1.69271 20.6221 1.0599 20.4059 0.632812 19.9736C0.205729 19.5465 -0.0078125 18.9085 -0.0078125 18.0596ZM1.53125 17.9658C1.53125 18.3304 1.625 18.609 1.8125 18.8018C2 18.9945 2.28125 19.0908 2.65625 19.0908H9.71094C10.0859 19.0908 10.3672 18.9945 10.5547 18.8018C10.7474 18.609 10.8438 18.3304 10.8438 17.9658V12.2314H6.71875C6.16667 12.2314 5.7526 12.096 5.47656 11.8252C5.20052 11.5492 5.0625 11.1299 5.0625 10.5674V6.29395H2.66406C2.28385 6.29395 2 6.3903 1.8125 6.58301C1.625 6.77572 1.53125 7.05176 1.53125 7.41113V17.9658ZM6.875 10.8799H10.6328L6.41406 6.59082V10.4189C6.41406 10.5804 6.45052 10.6976 6.52344 10.7705C6.59635 10.8434 6.71354 10.8799 6.875 10.8799Z"/></svg>`,
  save: `<svg viewBox="0 0 12 15"><path d="M5.98438 0.692383C6.23438 0.692383 6.4375 0.773112 6.59375 0.93457C6.75521 1.09603 6.83594 1.30436 6.83594 1.55957V8.8252L6.76562 10.4658L8.84375 8.17676L10.4531 6.59863C10.526 6.52051 10.6146 6.45801 10.7188 6.41113C10.8281 6.36426 10.9427 6.34082 11.0625 6.34082C11.3021 6.34082 11.5 6.42155 11.6562 6.58301C11.8125 6.74447 11.8906 6.94759 11.8906 7.19238C11.8906 7.30176 11.8672 7.40853 11.8203 7.5127C11.7734 7.61686 11.7031 7.71582 11.6094 7.80957L6.61719 12.7471C6.53385 12.8356 6.4375 12.9059 6.32812 12.958C6.21875 13.0101 6.10417 13.0361 5.98438 13.0361C5.85938 13.0361 5.74219 13.0101 5.63281 12.958C5.52344 12.9059 5.42708 12.8356 5.34375 12.7471L0.351562 7.80957C0.263021 7.71582 0.195312 7.61686 0.148438 7.5127C0.101562 7.40853 0.078125 7.30176 0.078125 7.19238C0.078125 6.94759 0.15625 6.74447 0.3125 6.58301C0.46875 6.42155 0.666667 6.34082 0.90625 6.34082C1.02604 6.34082 1.13802 6.36426 1.24219 6.41113C1.34635 6.45801 1.4375 6.52051 1.51562 6.59863L3.11719 8.17676L5.20312 10.4736L5.125 8.8252V1.55957C5.125 1.30436 5.20312 1.09603 5.35938 0.93457C5.52083 0.773112 5.72917 0.692383 5.98438 0.692383ZM0.8125 13.0127H11.1328C11.3776 13.0127 11.5781 13.0934 11.7344 13.2549C11.8906 13.4163 11.9688 13.6169 11.9688 13.8564C11.9688 14.096 11.8906 14.2965 11.7344 14.458C11.5781 14.6195 11.3776 14.7002 11.1328 14.7002H0.8125C0.578125 14.7002 0.382812 14.6195 0.226562 14.458C0.0703125 14.2965 -0.0078125 14.096 -0.0078125 13.8564C-0.0078125 13.6169 0.0703125 13.4163 0.226562 13.2549C0.382812 13.0934 0.578125 13.0127 0.8125 13.0127Z"/></svg>`,
  check: `<svg viewBox="0 0 14 14"><path d="M5.28125 13.6611C4.90625 13.6611 4.58594 13.4945 4.32031 13.1611L0.273438 8.09863C0.174479 7.97884 0.101562 7.86165 0.0546875 7.74707C0.0130208 7.63249 -0.0078125 7.5153 -0.0078125 7.39551C-0.0078125 7.12467 0.0807292 6.90072 0.257812 6.72363C0.440104 6.54655 0.669271 6.45801 0.945312 6.45801C1.26302 6.45801 1.53125 6.60124 1.75 6.8877L5.25 11.3799L12.0312 0.606445C12.151 0.424154 12.2734 0.296549 12.3984 0.223633C12.5234 0.145508 12.6849 0.106445 12.8828 0.106445C13.1536 0.106445 13.375 0.192383 13.5469 0.364258C13.7188 0.530924 13.8047 0.749674 13.8047 1.02051C13.8047 1.12988 13.7865 1.24186 13.75 1.35645C13.7135 1.46582 13.6562 1.58301 13.5781 1.70801L6.23438 13.1533C6.00521 13.4919 5.6875 13.6611 5.28125 13.6611Z"/></svg>`,
  edit: `<svg viewBox="0 0 23.6475 23.3041"><rect height="23.3041" opacity="0" width="23.6475" x="0" y="0"/><path d="M15.5591 4.88935L6.08643 4.88935C5.10986 4.88935 4.56299 5.41669 4.56299 6.43232L4.56299 17.5163C4.56299 18.5319 5.10986 19.0495 6.08643 19.0495L17.2095 19.0495C18.186 19.0495 18.7231 18.5319 18.7231 17.5163L18.7231 8.12957L20.2954 6.55445L20.2954 17.5944C20.2954 19.6159 19.27 20.6218 17.229 20.6218L6.05713 20.6218C4.02588 20.6218 2.99072 19.6159 2.99072 17.5944L2.99072 6.34443C2.99072 4.33271 4.02588 3.31708 6.05713 3.31708L17.1313 3.31708Z"/><path d="M9.61182 14.2936L11.5161 13.4636L20.6372 4.35224L19.2993 3.03388L10.188 12.1452L9.30908 13.9811C9.23096 14.1472 9.42627 14.3718 9.61182 14.2936ZM21.3599 3.63935L22.063 2.91669C22.395 2.56513 22.395 2.09638 22.063 1.77412L21.8384 1.53974C21.5356 1.23701 21.0571 1.27607 20.7349 1.58857L20.022 2.29169Z"/></svg>`,
  outbound: `<svg viewBox="0 0 24 24" class="outbound_link"><path d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25"/></svg>`,
  import: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3"/></svg>`,
  // Contacts-footer actions. export = arrow up out of the tray (mirror of import); trash = Clear all.
  // Stroke-based with currentColor so they follow the link color (and its hover light-up).
  export: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M7.5 7.5 12 3m0 0 4.5 4.5M12 3v13.5"/></svg>`,
  trash: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13M9 7V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v3"/></svg>`,
  // Cancel's "✗", the counterpart to Confirm's check — only used where a text Cancel sits beside an iconed Confirm.
  close: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M5 5 19 19M19 5 5 19"/></svg>`,
  // "Show QR" toggle on the receive-a-file link. Filled QR glyph (three finder rings + a few modules);
  // fill-rule evenodd carves the ring holes; fill via currentColor so it follows the link color on hover.
  qr: `<svg viewBox="0 0 24 24" fill-rule="evenodd"><path d="M3 3h7v7h-7zm2 2h3v3h-3zM14 3h7v7h-7zm2 2h3v3h-3zM3 14h7v7h-7zm2 2h3v3h-3zM14 14h3v3h-3zM18.5 14h2.5v2.5h-2.5zM14 18.5h2.5v2.5h-2.5zM18.5 18.5h2.5v2.5h-2.5z"/></svg>`,
  // Unlock button's "touch to unlock" biometric affordance (a fingerprint). Stroke-based so it inherits
  // the button's text color via currentColor — white on the solid-blue Unlock button. This is a biometric
  // cue, NOT the identity-verification fingerprint deliberately left unbuilt (see DESIGN.md Appendix A).
  fingerprint: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4"/><path d="M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2"/></svg>`,
  // Update-notice action icons (stroke + currentColor, same family as import/export/trash/close):
  // download = install the update; doc = open the changelog; clock = "Later" (defer).
  download: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 20h14"/></svg>`,
  doc: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M9 13h6M9 17h5"/></svg>`,
  clock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`,
};

// External-link affordance: the menu's box-arrow glyph, inline, inheriting the link's color.
const EXT_ICON = SVG.outbound.replace("outbound_link", "ext_icon");
const extLink = (href: string, text: string) =>
  `<a class="borderless msg_link" href="${href}" target="_blank" rel="noopener noreferrer">${text}${EXT_ICON}</a>`;
// Same, but ending a sentence: keeps the link + its period on one line so the "." never wraps alone
// onto a new line (the external-link icon is an atomic inline, which would otherwise allow a break).
const extLinkDot = (href: string, text: string) => `<span class="nobreak">${extLink(href, text)}.</span>`;

const RP_ID = deploymentRpId();
const NS = new Namespace(RP_ID);
const SET = new NamespaceSet([RP_ID]);
const APP_VERSION = versionManifest.current; // the version string this bundle shipped as
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const $ = (id: string) => document.getElementById(id)!;
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
// Strip Unicode bidi override/embedding/isolate controls (U+202A–202E, U+2066–2069). A sender-controlled
// filename like "photo<U+202E>gpj.exe" otherwise displays/saves as "photo.jpg" but lands on disk as .exe.
// Override/isolate chars only — NOT the LRM/RLM marks (U+200E/200F) that legitimate RTL filenames use.
const stripBidi = (s: string) => s.replace(/[\u202a-\u202e\u2066-\u2069]/g, "");
let mainInner: HTMLElement;
let identity: Identity | null = null;
let allowAutoScroll = false; // suppressed during the intro so the page doesn't auto-scroll on load (mobile)
let createdThisSession = false; // true once a filekey is created this page-load, so the recovery reminder only fires on a genuine return-visit authenticate
let statusCount = 0;
// Share model: each Share opens its OWN recipient prompt bound to that file, so different files
// in one session can go to different recipients (no single sticky global recipient).
type ShareFile = { plaintext: Blob; name: string; mime: string };

// v1 scrollToBottom (only scrolls once the feed fills ~3/4 of the viewport).
function scrollToBottom() {
  if (!allowAutoScroll) return; // hold the page still during the intro (no jump on mobile load)
  const three_quarters = document.body.clientHeight * 0.75;
  if (mainInner.clientHeight >= three_quarters) window.scroll(0, document.body.scrollHeight + document.body.scrollHeight / 10);
}
const setIcon = (el: Element, cls: string) => el.querySelector("svg")!.setAttribute("class", cls);

// ---- typewriter: char_speed = characters per animation frame (v1 std_fillTextBoxAnimation) ----
type Seg = string | { t: string; b?: boolean } | { link: string; onClick: () => void } | { html: string };
function typeInto(el: HTMLElement, text: string, perFrame: number): Promise<void> {
  if (REDUCED) { el.textContent = text; scrollToBottom(); return Promise.resolve(); }
  return new Promise((resolve) => {
    let i = 0;
    const frame = () => { i += perFrame; el.textContent = text.slice(0, i); scrollToBottom(); i < text.length ? requestAnimationFrame(frame) : resolve(); };
    requestAnimationFrame(frame);
  });
}
// Typewriter for rich HTML (menu panels, requirements, inline links): rebuilds the DOM
// incrementally — cloning each element as the cursor reaches it and typing each text node
// char-by-char — so structured content reveals progressively, like plain messages.
function typeHtmlInto(dest: HTMLElement, html: string, perFrame: number): Promise<void> {
  const src = document.createElement("div");
  src.innerHTML = html;
  if (REDUCED) { dest.innerHTML = html; scrollToBottom(); return Promise.resolve(); }
  const typeText = (tn: Text, text: string) => new Promise<void>((resolve) => {
    let i = 0;
    const frame = () => { i += perFrame; tn.data = text.slice(0, i); scrollToBottom(); i < text.length ? requestAnimationFrame(frame) : resolve(); };
    requestAnimationFrame(frame);
  });
  const walk = async (from: Node, to: Node): Promise<void> => {
    for (const child of Array.from(from.childNodes)) {
      if (child.nodeType === Node.TEXT_NODE) {
        const tn = document.createTextNode("");
        to.appendChild(tn);
        await typeText(tn, (child as Text).data);
      } else if (child.nodeType === Node.ELEMENT_NODE) {
        const clone = (child as Element).cloneNode(false);
        to.appendChild(clone);
        await walk(child, clone);
      }
    }
  };
  return walk(src, dest);
}
function appShell(dp = "std_dp", icon = "filekey_icon"): HTMLElement {
  const outer = document.createElement("div");
  outer.className = "std_outer";
  outer.innerHTML = `<div class="std_msg_inner"><span class="${dp}">${SVG.filekey}</span><span class="std_msg"></span></div>`;
  setIcon(outer.querySelector(`.${dp}`)!, icon);
  mainInner.appendChild(outer);
  return outer.querySelector(".std_msg") as HTMLElement;
}
async function appMsg(segs: Seg[], opts: { speed?: number; dp?: string; icon?: string } = {}): Promise<HTMLElement> {
  const speed = opts.speed ?? 8;
  const msg = appShell(opts.dp ?? "std_dp", opts.icon ?? "filekey_icon");
  scrollToBottom();
  for (const seg of segs) {
    if (typeof seg === "string") { const s = document.createElement("span"); msg.appendChild(s); await typeInto(s, seg, speed); }
    else if ("t" in seg) { const s = document.createElement(seg.b ? "strong" : "span"); msg.appendChild(s); await typeInto(s, seg.t, speed); }
    else if ("link" in seg) { const a = document.createElement("span"); a.className = "msg_clickable no_select"; a.textContent = seg.link; a.addEventListener("click", seg.onClick); msg.appendChild(a); if (!REDUCED) await new Promise((r) => setTimeout(r, 40)); }
    else { const s = document.createElement("span"); msg.appendChild(s); await typeHtmlInto(s, seg.html, speed); }
  }
  scrollToBottom();
  return msg; // returned so actionRow() can attach a choice row INSIDE this same bubble
}
// A choice row attached inside a chat-message bubble (pass the element appMsg returns) — distinct actions as
// blue primary + muted secondary chips, the Confirm/Cancel + Save/Skip vocabulary. Use this instead of
// cramming multiple action links into one appMsg separated by a "·".
function actionRow(host: HTMLElement, actions: { label: string; muted?: boolean; icon?: string; onClick: () => void }[]): void {
  const row = document.createElement("div");
  row.className = "msg_actions";
  for (const a of actions) {
    const s = document.createElement("span");
    s.className = `${a.muted ? "cancel_pub_key" : "confirm_pub_key"} no_select`;
    if (a.icon) s.innerHTML = `${a.icon}<span>${esc(a.label)}</span>`;
    else s.textContent = a.label;
    s.addEventListener("click", a.onClick);
    row.appendChild(s);
  }
  host.appendChild(row);
  scrollToBottom();
}
// Like actionRow, but renders REAL buttons (the .dc_btn vocabulary: solid-blue primary + ghost outline)
// with an optional leading icon — for the first-run moment that earns a tappable button over an inline
// link (Unlock / Create). DESIGN.md: distinct choices belong in a row, never two inline links.
function buttonRow(host: HTMLElement, buttons: { label: string; icon?: string; ghost?: boolean; onClick: () => void }[]): void {
  const row = document.createElement("div");
  row.className = "auth_row";
  for (const b of buttons) {
    const btn = document.createElement("button");
    btn.className = `dc_btn auth_btn ${b.ghost ? "dc_btn_ghost" : "dc_btn_primary"} no_select`;
    btn.innerHTML = `${b.icon ?? ""}<span>${esc(b.label)}</span>`;
    btn.addEventListener("click", b.onClick);
    row.appendChild(btn);
  }
  host.appendChild(row);
  scrollToBottom();
}
const ERR = { speed: 4, dp: "failed_dp", icon: "failed_filekey_icon" };   // v1 getErrorParams
const WARN = { speed: 2, dp: "warning_dp", icon: "warning_filekey_icon" }; // v1 getWarningParams

// ---- animated "Encrypting…/Decrypting…" status (v1 set3dotStatusAnimation) ----
class StatusMsg {
  msg: string; el: HTMLElement; cancelEl: HTMLElement; outer: HTMLElement; active = true; cancelled = false; start = performance.now();
  constructor(label: boolean | string) {
    this.msg = typeof label === "string" ? label : label ? "Encrypting" : "Decrypting";
    this.outer = document.createElement("div");
    this.outer.className = "std_status_outer";
    this.outer.innerHTML = `<div class="std_status_inner"><span class="std_dp">${SVG.filekey}</span><span class="std_status" id="status_${statusCount++}"></span><span class="std_status_cancel no_select" style="display:none;margin-left:6px"><span style="color:var(--fk-faint)">·</span><span class="fk_cancel_act" style="color:var(--fk-link);font-weight:500;cursor:pointer;margin-left:6px">Cancel</span></span></div>`;
    setIcon(this.outer.querySelector(".std_dp")!, "filekey_icon");
    mainInner.appendChild(this.outer);
    this.el = this.outer.querySelector(".std_status") as HTMLElement;
    this.cancelEl = this.outer.querySelector(".std_status_cancel") as HTMLElement;
    scrollToBottom();
    const tick = () => { if (!this.active) return; const s = Math.round((performance.now() - this.start) / 1000) % 3; this.el.textContent = this.msg + (s === 0 ? "." : s === 1 ? ".." : "..."); requestAnimationFrame(tick); };
    tick();
  }
  /** Show the Cancel affordance (streaming ops only). Main-thread loops poll `cancelled`; worker jobs
   *  pass `onCancel` to terminate the worker. Both bail before any partial output is saved. */
  enableCancel(onCancel?: () => void) {
    this.cancelEl.style.display = "";
    (this.cancelEl.querySelector(".fk_cancel_act") as HTMLElement).addEventListener("click", () => { this.cancel(); onCancel?.(); });
  }
  cancel() {
    if (this.cancelled) return;
    this.cancelled = true;
    this.active = false;
    this.el.textContent = `${this.msg}… Cancelled`;
    this.cancelEl.style.display = "none";
  }
  progress(done: number, total: number) {
    if (this.cancelled) return; // keep the "Cancelled" text; ignore in-flight progress from the last chunk
    this.active = false; // halt the cycling-dots animation; show byte progress instead
    this.el.textContent = `${this.msg}… ${fmtBytes(done)} of ${fmtBytes(total)}`;
  }
  finish(label: string) { this.active = false; this.el.textContent = label; this.cancelEl.style.display = "none"; }
  done() { this.finish(this.msg + "... Done!"); }
  fail() { this.active = false; this.outer.remove(); }
}

// ---- file cards (v1 html_newFileUpload / html_newDownload) ----
// Middle-ellipsis for filenames: pin the tail (extension) and ellipsize the head, so a long name
// like "Screenshot ….png.filekey" stays one clean line instead of breaking mid-word on mobile.
function fnameHtml(filename: string): string {
  filename = stripBidi(filename); // neutralize bidi-override extension spoofing before display
  const safe = esc(filename);
  if (filename.length <= 16) return `<span class="file_title" title="${safe}">${safe}</span>`;
  const tailLen = Math.min(12, Math.ceil(filename.length * 0.35));
  const head = esc(filename.slice(0, filename.length - tailLen));
  const tail = esc(filename.slice(filename.length - tailLen));
  return `<span class="file_title fname" title="${safe}"><span class="fname_head">${head}</span><span class="fname_tail">${tail}</span></span>`;
}
function uploadCard(filename: string, typeLabel: string, isEncrypted: boolean) {
  const outer = document.createElement("div");
  outer.className = "std_upload_outer";
  outer.innerHTML = `<div class="std_uploaded set_right"><div class="icon_container">${isEncrypted ? SVG.logo : SVG.file}</div><div class="std_file_container">${fnameHtml(filename)}<span class="file_status">${esc(typeLabel)}</span></div></div>`;
  setIcon(outer.querySelector(".icon_container")!, "file_icon");
  mainInner.appendChild(outer);
  scrollToBottom();
}
function downloadCard(filename: string, typeLabel: string, isEncrypted: boolean, dataBlob: Blob, shareSource: Blob, originalName: string, mime: string) {
  const outer = document.createElement("div");
  outer.className = "std_dl_outer";
  outer.innerHTML = `<div class="std_download"><div class="std_inner_flex"><div class="icon_container some_background">${isEncrypted ? SVG.logo : SVG.file}</div><div class="std_file_container">${fnameHtml(filename)}<span class="file_status">${esc(typeLabel)}</span><div class="download_icon_container"><span class="dl_action share_act">${SVG.share} Share</span><span class="dl_action save_act">${SVG.save} Save</span></div></div></div></div>`;
  setIcon(outer.querySelector(".icon_container")!, "file_icon");
  setIcon(outer.querySelector(".share_act")!, "dl_icon slight_vert_padding");
  setIcon(outer.querySelector(".save_act")!, "save_icon");
  (outer.querySelector(".save_act") as HTMLElement).addEventListener("click", () => void saveBlob(dataBlob, filename));
  (outer.querySelector(".share_act") as HTMLElement).addEventListener("click", () => onShareClick(shareSource, originalName, mime));
  mainInner.appendChild(outer);
  scrollToBottom();
}
// Deliver a recipient-encrypted file. Everything FileKey shares is already encrypted, so this is purely a
// hand-off choice: "Send" opens the OS share sheet (Signal, Mail, AirDrop, … — the sheet is the target
// list), "Save" downloads. Send only appears where the browser can share files (mobile, some desktop);
// elsewhere it falls back to Save alone. Nothing is persisted — it just hands off a file you already made.
function canSendFile(blob: Blob, filename: string): boolean {
  try {
    if (typeof navigator.canShare !== "function") return false;
    // Web Share for files works on touch devices (phones/tablets). Desktop browsers often report
    // canShare=true but share() then throws (confirmed on desktop Chrome), so gate on a coarse
    // (touch) primary pointer — "Send" only appears where a real OS share sheet exists.
    if (!window.matchMedia || !window.matchMedia("(pointer: coarse)").matches) return false;
    return navigator.canShare({ files: [new File([blob], filename, { type: "application/octet-stream" })] });
  } catch { return false; }
}
async function sendFile(blob: Blob, filename: string) {
  try { await navigator.share({ files: [new File([blob], filename, { type: "application/octet-stream" })] }); }
  catch (e) {
    if ((e as Error).name === "AbortError") return; // user dismissed the sheet — nothing to do
    console.error("FileKey: send failed —", e);
    await saveBlob(blob, filename);
    await appMsg(["This device couldn't open a share sheet, so the file was saved to your downloads instead."], { speed: 6 });
  }
}

function sanitizeName(name: string) { return (stripBidi(name).replace(/[\/\\]/g, "_").replace(/[\x00-\x1f]/g, "").trim() || "filekey-output").slice(0, 200); }
// Best-effort detection of a storage-constrained context (notably private/incognito, which caps
// origin storage hard) so a large-file failure can say so rather than a generic "try again".
async function storageTooSmallFor(bytes: number): Promise<boolean> {
  try { const est = await navigator.storage?.estimate?.(); if (!est || typeof est.quota !== "number") return false; return est.quota - (est.usage ?? 0) < bytes; } catch { return false; }
}
// Save a fully-assembled Blob. Prefers the native save picker where available (great for huge files —
// it streams to disk with no object-URL size limit), else a universal object-URL download (Firefox/
// Safari/mobile). NOT used as a streaming sink, so it never gates browser support on the FS Access API.
async function saveBlob(blob: Blob, filename: string) {
  const name = sanitizeName(filename);
  const big = blob.size >= STREAM_THRESHOLD; // large files get a progress / "keep tab open" note; every save is confirmed
  const w = window as unknown as { showSaveFilePicker?: (o: unknown) => Promise<{ createWritable: () => Promise<{ write: (b: Blob) => Promise<void>; close: () => Promise<void> }> }> };
  if (w.showSaveFilePicker) {
    let st: StatusMsg | null = null;
    try {
      const h = await w.showSaveFilePicker({ suggestedName: name });
      const ws = await h.createWritable();
      // The native write streams to disk and ws.close() resolves only when fully flushed, so this
      // Saving → Saved is a *true* completion signal (the object-URL path below can't offer one). The
      // picker already resolved here, so the user committed to a location; cancelling it threw above.
      st = new StatusMsg("Saving");
      await ws.write(blob); await ws.close();
      st.finish("Saved ✓");
      return;
    } catch (e) {
      st?.fail(); // drop the status whether the user cancelled the picker or the write itself failed
      if ((e as Error).name === "AbortError") return;
      // non-abort failure: fall through to the universal object-URL download
    }
  }
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.click();
  // An <a download> hands the blob to the browser's own download manager — there's no completion callback,
  // so we can't show "done" (the browser's download UI does). Frame it as a local save, not a network
  // transfer, and for a big file note that closing the tab early can interrupt the browser writing the blob.
  void appMsg([big
    ? "Your browser is saving the encrypted file to your downloads (nothing leaves your device). It's a large file, so keep this tab open until your browser shows the download finished."
    : "Saved to your downloads."], { speed: 6 });
  // Keep the URL valid long enough for the download to flush — scale ~1s/MB (60s floor, 10min cap);
  // freed on tab close regardless. (Chrome's native picker path above doesn't reach here.)
  const ttl = Math.min(600_000, Math.max(60_000, Math.ceil(blob.size / (1024 * 1024)) * 1000));
  setTimeout(() => URL.revokeObjectURL(a.href), ttl);
}

// ---- streaming helpers (large files: read the File in chunks, write a Blob-of-Blobs) ----
const STREAM_THRESHOLD = 64 * 1024 * 1024; // files ≥64 MB stream; smaller ones use the in-memory path (AES-GCM ~1GB/s, so the byte-progress line only earns its keep past this size)
function fmtBytes(n: number): string {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${Math.round(n / 1024 ** 2)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KB`;
  return `${n} B`;
}
// A Blob-backed ByteSource for the DOM-free core (a File IS a Blob). onRead reports the high-water
// byte offset read — used to drive encrypt progress, where slices advance sequentially through the plaintext.
function blobSource(blob: Blob, onRead?: (highWater: number) => void): ByteSource {
  return {
    size: blob.size,
    async slice(start: number, end: number): Promise<Uint8Array> {
      const stop = Math.min(end, blob.size);
      const u = new Uint8Array(await blob.slice(start, stop).arrayBuffer());
      onRead?.(stop);
      return u;
    },
  };
}

// ---- off-main-thread crypto client (large files only) — runs the streaming core in web/worker.ts ----
// One Worker per job, terminated on completion or cancel: no shared state, and cancel = terminate (instant).
// Identity is derived on the main thread (WebAuthn/PRF can't run in a Worker), so the caller passes the
// already-derived, structured-cloneable key material; the worker rebuilds Identity/Namespace from it.
type JobProgress = (done: number, total: number) => void;
type JobOutcome = { blob: Blob; metadata?: Metadata; shareSource?: Blob } | { cancelled: true };
function runCryptoJob(job: Record<string, unknown>, onProgress?: JobProgress): { result: Promise<JobOutcome>; cancel: () => void } {
  const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
  let settled = false;
  let resolveOutcome!: (o: JobOutcome) => void; // captured so cancel() can settle the promise from outside the executor
  const end = (fn: () => void) => { if (settled) return; settled = true; worker.terminate(); fn(); };
  const result = new Promise<JobOutcome>((resolve, reject) => {
    resolveOutcome = resolve;
    worker.onmessage = (e: MessageEvent) => {
      const m = e.data as { kind: string; done?: number; total?: number; blob?: Blob; metadata?: Metadata; shareSource?: Blob; code?: string; message?: string };
      if (m.kind === "progress") onProgress?.(m.done ?? 0, m.total ?? 0);
      else if (m.kind === "done") end(() => resolve({ blob: m.blob!, metadata: m.metadata, shareSource: m.shareSource }));
      // Rebuild a coded FileKeyError (so the decrypt catch's `instanceof`/`.code` checks still work); a
      // plain Error for anything uncoded (e.g. a storage-quota failure → the incognito message path).
      else if (m.kind === "error") end(() => reject(m.code ? new FileKeyError(m.message ?? "", m.code) : new Error(m.message ?? "worker error")));
    };
    worker.onerror = (ev) => end(() => reject(new Error((ev as ErrorEvent).message || "encryption worker failed to start")));
    worker.postMessage(job);
  });
  return { result, cancel: () => end(() => resolveOutcome({ cancelled: true })) };
}

// ---- identity (v1 genNewPasskey -> "Now tap to unlock" -> loadSecKey) ----
// Per-browser record of filekeys created here (timestamps only — no keys, no secrets, so it's fine under
// the "no secrets stored" rule). Two uses: warn before an accidental *second* filekey (a separate identity
// whose files won't interchange), and give additional keys a dated name so the OS passkey picker can tell
// them apart. Per-browser by nature: it can't see a key created on a different device/browser.
const CREATED_LOG_KEY = "filekey.created";
function createdLog(): number[] {
  try { const a = JSON.parse(localStorage.getItem(CREATED_LOG_KEY) || "[]"); return Array.isArray(a) ? a.filter((x): x is number => typeof x === "number") : []; }
  catch { return []; }
}
function recordCreated(at: number): void {
  try { const a = createdLog(); a.push(at); localStorage.setItem(CREATED_LOG_KEY, JSON.stringify(a)); } catch { /* storage blocked → can't track on this browser */ }
}
const fmtKeyDate = (ts: number): string => {
  try { return new Date(ts).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }); } catch { return "an earlier date"; }
};

// Shown when WebAuthn PRF isn't available — either the browser-level pre-check failed, or the
// authenticator failed the post-create check. junkPasskey=true means a passkey was just created
// that can't do PRF, so we also point the user at removing it.
async function showPrfUnsupported(junkPasskey: boolean) {
  await appMsg([
    junkPasskey
      ? `This passkey doesn't support PRF, which FileKey needs. You can remove the new "FileKey" passkey in your device's passkey settings. `
      : `FileKey needs a passkey that supports PRF, which this browser or device doesn't support yet. `,
    { link: "See what works.", onClick: () => void displayRequirements() },
  ], ERR);
}
async function genNewPasskey() {
  if (identity) return;
  const prior = createdLog();
  if (prior.length) {
    // They already made a filekey on this browser — most often they actually meant to sign in. Confirm
    // intent and offer the right path instead of silently minting a second, non-interchangeable identity.
    const m = await appMsg([`Heads up: you already created a filekey on this device on ${fmtKeyDate(prior[prior.length - 1]!)}. A new one is a separate identity, so files locked with your existing filekey won't open with it.`]);
    actionRow(m, [
      { label: "Use existing", onClick: () => void loadSecKey() },
      { label: "Create new", muted: true, onClick: () => void doEnroll(true) },
    ]);
    return;
  }
  await doEnroll(false);
}
async function doEnroll(additional: boolean) {
  if (identity) return;
  // Pre-flight: if the browser definitively lacks PRF, say so without minting a junk passkey.
  if ((await prfBrowserSupport()) === false) { await showPrfUnsupported(false); return; }
  const now = Date.now();
  // First key on this browser stays a clean "FileKey"; extras get a dated name so they're distinguishable
  // in the authenticator's passkey picker (which otherwise shows two identical "FileKey" entries).
  const name = additional ? `FileKey · ${fmtKeyDate(now)}` : "FileKey";
  try { await enrollPasskey(name); }
  catch (e) {
    console.error("FileKey: passkey creation failed —", e);
    if ((e as Error).name === "NotAllowedError") return;
    // Browser allowed PRF but the authenticator didn't (e.g. older Windows Hello): a passkey got
    // created that can't do PRF — tell them, and that they can remove it.
    if (/PRF/i.test((e as Error).message)) { await showPrfUnsupported(true); return; }
    await appMsg(["Failed to create your filekey. Please try again."], ERR);
    return;
  }
  recordCreated(now);
  createdThisSession = true; // brand-new user: skip the recovery reminder on the create -> authenticate hop
  await appMsg(["Filekey created. ", { link: "Now tap to unlock", onClick: () => void loadSecKey() }, "."], { speed: 4 });
}
// Glanceable identity for the Your FileKey menu. No passkey name is available on
// auth, so we derive a deterministic identicon + 8-char fingerprint from the public
// key (identical on any device for the same filekey; distinguishes multiple keys).
function identicon(hex: string): string {
  const bytes = (hex.match(/.{2}/g) || []).map((h) => parseInt(h, 16));
  const bit = (i: number) => ((bytes[(i / 8) | 0] ?? 0) >> (7 - (i % 8))) & 1;
  const hue = (((bytes[0] ?? 0) * 360) / 256) | 0;
  const fg = `hsl(${hue} 56% 47%)`, bg = `hsl(${hue} 42% 93%)`;
  const N = 5, cell = 10;
  let cells = "";
  for (let r = 0; r < N; r++) for (let c = 0; c < 3; c++)
    if (bit(r * 3 + c)) for (const cc of c === 2 ? [2] : [c, 4 - c])
      cells += `<rect x="${cc * cell}" y="${r * cell}" width="${cell}" height="${cell}"/>`;
  return `<svg viewBox="0 0 ${N * cell} ${N * cell}" width="100%" height="100%"><rect width="100%" height="100%" fill="${bg}"/><g fill="${fg}">${cells}</g></svg>`;
}
function renderIdentityHeader(): void {
  const id = identity;
  if (!id) return;
  const hex = identityFingerprint(id.staticPkRaw).hex.toUpperCase();
  $("acct_identity").innerHTML = `<span class="id_icon">${identicon(hex)}</span><div class="id_meta"><div class="id_name">Your FileKey</div><div class="id_fp">${hex.replace(/(.{4})(.{4})/, "$1 $2")}</div></div>`;
}
async function loadSecKey() {
  if (identity) return;
  if ((await prfBrowserSupport()) === false) { await showPrfUnsupported(false); return; }
  try {
    const prf = await getPrfSecret();
    try { identity = await deriveIdentityFromPrf(prf, NS); } finally { prf.fill(0); } // scrub the PRF secret once identity is derived (best-effort)
  }
  catch (e) {
    console.error("FileKey: authentication failed —", e);
    if ((e as Error).name === "NotAllowedError") return;
    if (/PRF/i.test((e as Error).message)) { await showPrfUnsupported(false); return; }
    await appMsg([`Failed to unlock. Please try again.`], ERR); return;
  }
  await Contacts.loadContacts(identity!, SET); // local address book (public keys + your nicknames), decrypted into memory
  await appMsg(["Filekey unlocked. Now drop files to encrypt or decrypt them!"]);
  $("drop_container").style.display = "flex";
  document.body.classList.add("fk-authed"); // reveals the Your FileKey control (sliders) in the top bar
  renderIdentityHeader();
  scrollToBottom();
  // Returning user (didn't just create one): a gentle, one-time recovery reminder, well clear of onboarding.
  if (!createdThisSession) void maybeRecoveryNudge();
}
async function ensureAuthed(): Promise<boolean> {
  if (identity) return true;
  await loadSecKey();
  return identity != null;
}

// ---- file flow: route a batch of dropped/picked items (files + folders) ----
// Loose encrypted files decrypt individually; a lone plaintext file encrypts directly; any folder
// (or 2+ plaintext items) is zipped into one archive and encrypted as a single .filekey. Decryption
// is unchanged — a bundle just decrypts back to its .zip, which the user unpacks.
async function handleItems(items: BundleItem[]) {
  if (!items.length) return;
  const toDecrypt: BundleItem[] = [], toEncrypt: BundleItem[] = [], toLegacy: BundleItem[] = [], toUnsupported: BundleItem[] = [];
  for (const it of items) {
    if (it.fromFolder) { toEncrypt.push(it); continue; }            // folder contents are always content to bundle
    const cls = await classifyFile(it.file);
    if (cls === "decrypt") toDecrypt.push(it);                      // valid FKEY header → this build can decrypt it
    else if (cls === "unsupported") toUnsupported.push(it);         // FKEY magic but wrong version/suite, or corrupt header
    else if (isLegacyName(it.file.name)) toLegacy.push(it);        // .filekey/.shared_filekey w/o FKEY magic → made by v1
    else toEncrypt.push(it);                                        // not a FileKey file → encrypt it
  }
  for (const it of toDecrypt) await decryptFile(it.file);
  for (const it of toUnsupported) await unsupportedFileCard(it.file);
  for (const it of toLegacy) await legacyHandoffCard(it.file);
  if (toEncrypt.length === 1 && !toEncrypt[0]!.fromFolder) await encryptSingle(toEncrypt[0]!.file);
  else if (toEncrypt.length) await encryptBundle(toEncrypt);
}

// Classify a dropped file by its 12-byte header (read without pulling the whole file):
//  "decrypt"     — a valid FKEY header this build can open
//  "unsupported" — FKEY magic matched but the version/suite is one we can't handle, or the header is corrupt
//  "plain"       — no FKEY magic (or too short to have one): not a FileKey file at all
async function classifyFile(file: File): Promise<"decrypt" | "unsupported" | "plain"> {
  try {
    parseHeader(new Uint8Array(await file.slice(0, HEADER_LEN).arrayBuffer()));
    return "decrypt";
  } catch (e) {
    const code = e instanceof FileKeyError ? e.code : "";
    // Wrong/short magic ⇒ not ours. Any other header failure means the magic matched but we can't open it.
    return code === "bad_magic" || code === "header_length" ? "plain" : "unsupported";
  }
}

// A file whose header carries the FKEY magic but a version/suite this build can't open (or a corrupt
// header). Don't re-encrypt it or send it to the v1 handoff — say so plainly.
async function unsupportedFileCard(file: File) {
  uploadCard(file.name, "FileKey file", true);
  await appMsg(
    ["This looks like a FileKey file, but it's an unsupported version or it's corrupted, so it can't be opened here."],
    WARN,
  );
}

async function decryptFile(file: File) {
  const isShared = /\.shared[._]filekey$/i.test(file.name);
  uploadCard(file.name, isShared ? "Shared File" : "Encrypted File", true);
  if (!(await ensureAuthed())) return;
  const st = new StatusMsg(false);
  try {
    if (file.size >= STREAM_THRESHOLD) {
      await decryptStreaming(file, st);
    } else {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const res = await decrypt({ file: bytes, namespaces: SET, resolveIdentity: async () => identity! });
      st.done();
      const mime = res.metadata.mimeType || "application/octet-stream";
      const ptBlob = new Blob([res.plaintext as unknown as BlobPart], { type: mime });
      downloadCard(res.metadata.filename, "File", false, ptBlob, ptBlob, res.metadata.filename, mime);
    }
  } catch (e) {
    console.error("FileKey: decrypt failed —", e);
    st.fail();
    const code = e instanceof FileKeyError ? e.code : "";
    let msg = "Failed to unlock file with this key. Please try again.";
    if (code === "wrong_namespace") msg = "This file was encrypted for a different FileKey site, so it can't be opened here.";
    else if (!(e instanceof FileKeyError) && await storageTooSmallFor(file.size * 2)) msg = "Couldn't unlock: your browser is low on storage for a file this size. Private/incognito mode is especially limited, so try a normal window.";
    await appMsg([msg], ERR);
  }
}

// Large files: stream-decrypt the dropped File chunk-by-chunk into a Blob-of-Blobs (never the whole
// file in memory). Policy A — the chunks generator throws on any auth/truncation failure, so a failed
// file is caught by decryptFile and never assembled into a downloadable output.
async function decryptStreaming(file: File, st: StatusMsg) {
  // Big file → decrypt in a Worker. A failed/truncated file rejects (no partial plaintext assembled), and the
  // rejection reaches decryptFile's catch with the original FileKeyError code intact (see runCryptoJob).
  const job = runCryptoJob({ kind: "decrypt", rpId: RP_ID, rpIds: [RP_ID], keyPair: identity!.keyPair, staticPk: identity!.staticPkRaw, file }, (d, t) => st.progress(d, t));
  st.enableCancel(job.cancel);
  const out = await job.result;
  if ("cancelled" in out) return; // dropped the decrypted prefix; nothing saved
  st.done();
  const mime = out.metadata?.mimeType || "application/octet-stream";
  const name = out.metadata?.filename || "file";
  downloadCard(name, "File", false, out.blob, out.blob, name, mime); // only offered after full authentication
}

// A file named like a FileKey file but lacking the FKEY magic header was made by the original v1 app
// (P-521 / different format this version can't read). Don't encrypt it — hand the user off to the v1 app.
function isLegacyName(name: string): boolean {
  return /\.(shared[._])?filekey$/i.test(name);
}

// The original v1 app lives on a "v1." subdomain of this deployment's registrable domain.
function v1AppUrl(): string {
  const apex = deploymentRpId();
  return apex.includes(".") ? `https://v1.${apex}` : "https://v1.filekey.app";
}

async function legacyHandoffCard(file: File) {
  const url = v1AppUrl();
  uploadCard(file.name, "Made with an earlier FileKey", true);
  await appMsg(
    [{ html: `This file was locked with an <b>earlier version of FileKey</b> that used a different format, so it can't be opened here. Unlock it at ${extLinkDot(url, url.replace(/^https:\/\//, ""))} Your same passkey works there.` }],
    { dp: "warning_dp", icon: "warning_filekey_icon" },
  );
}

// Recovery nudge: a one-time, dismissible heads-up after the first lock (encrypt-to-self),
// pointing at the recovery code. Shown at most once, and suppressed entirely if they've
// already opened recovery on their own — informed consent, not a recurring nag.
const RECOVERY_ACK_KEY = "filekey.recovery_acked";
const flagGet = (k: string) => { try { return localStorage.getItem(k) === "1"; } catch { return false; } };
const flagSet = (k: string) => { try { localStorage.setItem(k, "1"); } catch { /* storage blocked → may re-show next session */ } };
async function maybeRecoveryNudge() {
  if (flagGet(RECOVERY_ACK_KEY)) return;
  // Only nudge a profile with persistent state from a prior session. Incognito (and cleared profiles)
  // reset localStorage every visit, so the acked flag above can't dedupe; without this guard, someone
  // who lives in incognito with one passkey would be nagged every single session. No created-log means
  // no persistence, so stay quiet (recovery is still one tap away in the menu).
  if (!createdLog().length) return;
  flagSet(RECOVERY_ACK_KEY);
  await appMsg(["Have you saved a recovery code? It's the only way back into your files if you ever lose this passkey. ", { link: "Show recovery code", onClick: () => void revealRecovery() }], { speed: 4 });
}
async function encryptSingle(file: File) {
  uploadCard(file.name, "File", false);
  if (!(await ensureAuthed())) return;
  const st = new StatusMsg(true);
  try {
    const meta: Omit<Metadata, "originalSize"> = { filename: file.name, mimeType: file.type || "application/octet-stream", createdAtUnixMs: Date.now(), extras: new Map() };
    if (file.size >= STREAM_THRESHOLD) {
      // Big file → run the encrypt in a Worker so the main thread stays responsive (see runCryptoJob).
      const job = runCryptoJob({ kind: "encrypt", rpId: RP_ID, senderKeyPair: identity!.keyPair, senderPk: identity!.staticPkRaw, recipientPk: identity!.staticPkRaw, blob: file, metadata: meta }, (d, t) => st.progress(d, t));
      st.enableCancel(job.cancel);
      const out = await job.result;
      if ("cancelled" in out) return; // dropped in-flight output; nothing saved
      st.done();
      // shareSource is the original File (re-readable from disk) so Share re-streams without holding plaintext.
      downloadCard(`${file.name}.filekey`, "Encrypted File", true, out.blob, file, file.name, "application/octet-stream");
    } else {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const out = await encryptToSelf({ identity: identity!, plaintext: bytes, metadata: meta });
      st.done();
      downloadCard(`${file.name}.filekey`, "Encrypted File", true, new Blob([out as unknown as BlobPart]), new Blob([bytes as unknown as BlobPart], { type: file.type || "application/octet-stream" }), file.name, "application/octet-stream");
    }  } catch (e) {
    console.error("FileKey: file encrypt failed —", e);
    st.fail();
    await appMsg([(await storageTooSmallFor(file.size * 2)) ? "Couldn't encrypt: your browser is low on storage for a file this size. Private/incognito mode is especially limited, so try a normal window." : "Failed to encrypt this file. Please try again."], ERR);
  }
}

// Bundle names must stay distinct within a session, so repeated loose-file bundles (all named
// "filekey-bundle") don't collide in the list or overwrite each other on save. Suffix -2, -3, … on reuse.
const usedBundleNames = new Set<string>();
function uniqueBundleName(base: string): string {
  let name = base;
  for (let n = 2; usedBundleNames.has(name); n++) name = `${base}-${n}`;
  usedBundleNames.add(name);
  return name;
}

// Multiple files / folders → one .zip, encrypted as a single .filekey.
async function encryptBundle(items: BundleItem[]) {
  const name = uniqueBundleName(bundleName(items));
  const zipName = `${name}.zip`;
  uploadCard(name, `${items.length} ${items.length === 1 ? "file" : "files"}`, false);
  if (!(await ensureAuthed())) return;
  const st = new StatusMsg(true);
  try {
    const meta: Omit<Metadata, "originalSize"> = { filename: zipName, mimeType: "application/zip", createdAtUnixMs: Date.now(), extras: new Map() };
    const total = items.reduce((n, it) => n + it.file.size, 0);
    if (total >= STREAM_THRESHOLD) {
      // Big folder → zip + encrypt in a Worker (the zip's CRC32 is the biggest main-thread cost). Progress
      // spans both phases (zip read + encrypt ≈ 2x bytes). shareSource is the archive, returned for Share.
      const job = runCryptoJob({ kind: "zipEncrypt", rpId: RP_ID, senderKeyPair: identity!.keyPair, senderPk: identity!.staticPkRaw, recipientPk: identity!.staticPkRaw, items, totalBytes: total, metadata: meta }, (d, t) => st.progress(d, t));
      st.enableCancel(job.cancel);
      const out = await job.result;
      if ("cancelled" in out) return; // cancelled during zip or encrypt; nothing saved
      st.done();
      downloadCard(`${zipName}.filekey`, "Encrypted Bundle", true, out.blob, out.shareSource ?? new Blob([]), zipName, "application/octet-stream");
    } else {
      // Small folder → zip + encrypt on the main thread (fast; not worth the Worker round-trip).
      const zipBlob = await zipBundleToBlob(items);
      const parts: Blob[] = [];
      for await (const piece of encryptStream({ senderIdentity: identity!, recipientPkRaw: identity!.staticPkRaw, namespace: identity!.namespace, plaintext: blobSource(zipBlob), metadata: meta })) parts.push(new Blob([piece as unknown as BlobPart]));
      st.done();
      downloadCard(`${zipName}.filekey`, "Encrypted Bundle", true, new Blob(parts), zipBlob, zipName, "application/octet-stream");
    }  } catch (e) {
    console.error("FileKey: folder encrypt failed —", e); // surface the real cause (the message below is generic)
    st.fail();
    await appMsg([(await storageTooSmallFor(items.reduce((n, it) => n + it.file.size, 0) * 2)) ? "Couldn't encrypt: your browser is low on storage for files this large. Private/incognito mode is especially limited, so try a normal window or a smaller batch." : "Failed to encrypt these files. Please try again."], ERR);
  }
}

// ---- contacts: label helpers + post-share capture (data layer lives in web/contacts.ts) ----
const shortKey = (key: string) => (key.length > 22 ? `${key.slice(0, 12)}…${key.slice(-6)}` : key);
const contactLabel = (c: Contacts.Contact) => c.nickname || shortKey(c.key);
const avatarInitial = (c: Contacts.Contact) => { const n = c.nickname?.trim(); return n ? n[0]!.toUpperCase() : "•"; };

// After a successful share: if the recipient is already a saved contact, bump its recency (recent-first);
// if brand new, offer to save them — but only persist the contact if they add a nickname (skip = not saved).
async function rememberRecipient(key: string) {
  if (Contacts.findByKey(key)) { await Contacts.rememberUse(key); return; }
  await promptNickname(key);
}
async function promptNickname(key: string) {
  await appMsg([`Save ${shortKey(key)} to your contacts? Add a nickname so it's easy to pick next time:`], { speed: 4 });
  const tmp = document.createElement("div");
  tmp.innerHTML = `<div class="nickname_row set_right"><input id="nickname_input" class="nickname_input" type="text" placeholder="Nickname (e.g. Mom)" maxlength="40" autocomplete="off"><span id="nickname_save" class="nickname_btn no_select">Save</span><span id="nickname_skip" class="nickname_skip no_select">Skip</span></div>`;
  const row = tmp.firstElementChild as HTMLElement;
  mainInner.appendChild(row);
  const input = $("nickname_input") as HTMLInputElement;
  const saveBtn = $("nickname_save"), skipBtn = $("nickname_skip");
  scrollToBottom(); input.focus();
  let done = false;
  const finish = () => { done = true; input.setAttribute("readonly", "true"); input.style.backgroundColor = "var(--fk-fill)"; saveBtn.remove(); skipBtn.remove(); };
  const skip = async () => {
    if (done) return;
    done = true;
    row.remove(); // without a nickname we never saved the contact — leave nothing stranded
    await appMsg(["Okay, not saved to your contacts."], { speed: 4 });
  };
  const save = async () => {
    if (done) return;
    const name = input.value.trim();
    if (!name) { await skip(); return; } // no nickname → don't save (treated as skip)
    const res = await Contacts.addContact(key, name);
    if (!res.ok) {
      if (res.reason === "duplicate_nickname") { await appMsg([`"${name}" is already used by ${contactLabel(res.conflict)}. Try a different name.`], { speed: 6 }); return; }
      finish(); await appMsg([`Already in your contacts as ${contactLabel(res.conflict)}.`], { speed: 4 }); return; // duplicate_key (rare: guarded by findByKey above)
    }
    finish();
    await appMsg([`Saved "${name}" to your contacts.`], { speed: 4 });
  };
  saveBtn.addEventListener("click", () => void save());
  skipBtn.addEventListener("click", () => void skip());
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); void save(); } });
}

// Share (v1 triggerShare, reworked): each Share opens its OWN recipient prompt bound to that file,
// so different files in one session can go to different recipients. Contacts power a quick picker.
function onShareClick(plaintext: Blob, name: string, mime: string) {
  void openRecipientPrompt({ plaintext, name, mime });
}
async function openRecipientPrompt(file: ShareFile) {
  await appMsg([`Share "${file.name}". Enter the recipient's share key for secure sharing:`], { speed: 4 });
  // recent-contacts picker (above the input): click a contact to fill+confirm; typing the key filters it.
  // Local element refs (no ids) so multiple share prompts can coexist in one session.
  const picker = document.createElement("div");
  picker.className = "contacts_picker set_right";
  mainInner.appendChild(picker);
  // v1 html_newTextarea: right-aligned, auto-growing, Confirm (check) + Edit (pencil, hidden).
  const tmp = document.createElement("div");
  tmp.innerHTML = `<div class="pub_key_textarea_cont set_right"><textarea class="pub_key_textarea" placeholder="Enter recipient's share key" rows="1" spellcheck="false" autocapitalize="off" autocorrect="off" autocomplete="off"></textarea><div class="pub_key_actions"><span class="confirm_pub_key no_select">${SVG.check.replace("<svg", '<svg class="confirm_icon"')} <span>Confirm</span></span><span class="cancel_pub_key no_select">${SVG.close.replace("<svg", '<svg class="cancel_icon"')} <span>Cancel</span></span><span class="edit_pub_key no_select">${SVG.edit.replace("<svg", '<svg class="edit_icon"')} <span>Edit</span></span></div></div>`;
  const cont = tmp.firstElementChild as HTMLElement;
  mainInner.appendChild(cont);
  const ta = cont.querySelector(".pub_key_textarea") as HTMLTextAreaElement;
  const cancelBtn = cont.querySelector(".cancel_pub_key") as HTMLElement;
  const confirmBtn = cont.querySelector(".confirm_pub_key") as HTMLElement;
  const editBtn = cont.querySelector(".edit_pub_key") as HTMLElement;
  const grow = () => { ta.style.height = "auto"; ta.style.height = ta.scrollHeight + "px"; }; // auto-size to fit the (wrapping) key
  grow();
  const renderPicker = (filter = "") => {
    const all = Contacts.listContacts();
    if (!all.length) { picker.style.display = "none"; picker.innerHTML = ""; return; }
    const f = filter.trim().toLowerCase();
    const matches = (f ? all.filter((c) => (c.nickname || "").toLowerCase().includes(f) || c.key.toLowerCase().includes(f)) : all).slice(0, 8);
    picker.style.display = "flex";
    picker.innerHTML = `<span class="contacts_picker_label">${f ? "Matching contacts" : "Recent contacts"}</span>`;
    if (!matches.length) { picker.insertAdjacentHTML("beforeend", `<span class="contacts_picker_empty">No matches. Paste a share key below.</span>`); return; }
    for (const c of matches) {
      const chip = document.createElement("span");
      chip.className = "contact_chip no_select";
      chip.innerHTML = `<span class="contact_avatar">${esc(avatarInitial(c))}</span><span class="contact_chip_label">${esc(contactLabel(c))}</span>`;
      chip.addEventListener("click", () => { ta.value = c.key; grow(); void onConfirm(); });
      picker.appendChild(chip);
    }
  };
  ta.addEventListener("input", () => { grow(); renderPicker(ta.value); });
  scrollToBottom();
  let sent = false;
  const lock = () => { // recipient chosen + file sent: lock the field, show only Edit
    picker.style.display = "none";
    cancelBtn.style.display = "none";
    confirmBtn.style.display = "none";
    editBtn.style.display = "flex";
    ta.setAttribute("readonly", "true"); ta.style.backgroundColor = "var(--fk-fill)";
  };
  const unlock = () => { // editing the recipient: reopen the field + picker, show Confirm + Cancel again
    editBtn.style.display = "none";
    confirmBtn.style.display = "flex";
    cancelBtn.style.display = "flex";
    ta.removeAttribute("readonly"); ta.style.backgroundColor = "var(--fk-surface)";
    renderPicker("");
  };
  const onConfirm = async () => {
    const val = ta.value.trim();
    if (!val) return;
    try { decodeShareKey(val, SET); } catch { await appMsg(["Invalid share key."], { speed: 8 }); return; }
    lock();
    await encryptForRecipient(val, file);
    sent = true;
  };
  // Cancel before any send dismisses the whole prompt; while editing after a send it just re-locks (that file already went out).
  const onCancel = () => { if (sent) lock(); else { picker.remove(); cont.remove(); void appMsg(["Share cancelled."], { speed: 6 }); } };
  cancelBtn.addEventListener("click", onCancel);
  confirmBtn.addEventListener("click", onConfirm);
  editBtn.addEventListener("click", unlock);
  renderPicker();
}
// v1 handleShare: encrypt the plaintext to the chosen recipient and save it directly (no card).
async function encryptForRecipient(recipient: string, file: ShareFile, opts: { sender?: Identity; who?: string; remember?: boolean } = {}) {
  const big = file.plaintext.size >= STREAM_THRESHOLD;
  const st = big ? new StatusMsg(true) : null;
  try {
    const meta: Omit<Metadata, "originalSize"> = { filename: file.name, mimeType: file.mime, createdAtUnixMs: Date.now(), extras: new Map() };
    const { recipientPkRaw, namespace } = decodeShareKey(recipient, SET); // file's namespace comes from the share key
    let out: Blob;
    if (big) {
      const sender = opts.sender ?? identity!;
      const job = runCryptoJob({ kind: "encrypt", rpId: namespace.canonicalRpId, senderKeyPair: sender.keyPair, senderPk: sender.staticPkRaw, recipientPk: recipientPkRaw, blob: file.plaintext, metadata: meta }, (d, t) => st!.progress(d, t));
      st!.enableCancel(job.cancel);
      const r = await job.result;
      if ("cancelled" in r) return; // cancelled; nothing saved
      st!.done();
      out = r.blob;
    } else {
      const parts: Blob[] = [];
      for await (const piece of encryptStream({ senderIdentity: opts.sender ?? identity!, recipientPkRaw, namespace, plaintext: blobSource(file.plaintext), metadata: meta })) parts.push(new Blob([piece as unknown as BlobPart]));
      out = new Blob(parts, { type: "application/octet-stream" });
    }
    const sharedName = `${file.name}.shared.filekey`; // SPEC: .shared.filekey
    const nick = opts.who ?? Contacts.findByKey(recipient)?.nickname;
    const who = nick ? `for "${nick}"` : "for your recipient";
    // Deliver as an inline choice, not a second card (a card looked too much like the encrypted-file card).
    // Save works everywhere; Send (OS share sheet) only where the browser can share files.
    // Same copy + action row on every browser. Desktop usually lacks an OS file-share sheet, so the
    // Save-only case is what most people see; Save is always offered, Send… only where the sheet exists.
    const canSend = canSendFile(out, sharedName);
    const m = await appMsg([`"${file.name}" is encrypted ${who}. Only they can open it.`], { speed: 6 });
    const acts: { label: string; muted?: boolean; icon?: string; onClick: () => void }[] = [{ label: "Save", icon: SVG.save.replace("<svg", '<svg class="save_icon"'), onClick: () => void saveBlob(out, sharedName) }];
    if (canSend) acts.push({ label: "Send…", icon: SVG.share.replace("<svg", '<svg class="dl_icon"'), onClick: () => void sendFile(out, sharedName) });
    actionRow(m, acts);
    if (opts.remember !== false) await rememberRecipient(recipient); // add/refresh this recipient in the local address book
  } catch (e) { console.error("FileKey: share encrypt failed —", e); st?.fail(); await appMsg([`Couldn't encrypt for that recipient: ${esc((e as Error).message)}`], ERR); }
}

// ---- "send me a file" link (inbound / anonymous) ------------------------------------------------
// A "#to=<share key>" link lets ANYONE encrypt a file to the link owner using a throwaway one-time
// sender identity — no passkey, no account, no password. Pure public-key E2E; reuses the normal
// encrypt path.
function parseSendToHash(): { to: string; name?: string } | null {
  try {
    const raw = location.hash.replace(/^#/, "");
    if (!raw) return null;
    const p = new URLSearchParams(raw);
    const to = p.get("to");
    return to ? { to, name: p.get("name") || undefined } : null;
  } catch { return null; }
}
// CSPRNG bytes through the normal derivation = a valid one-time keypair (codex-confirmed). NS is this
// deployment's namespace, which the link's key must also be in (decodeShareKey validates it).
const deriveThrowawayIdentity = (): Promise<Identity> =>
  deriveIdentityFromPrf(crypto.getRandomValues(new Uint8Array(32)), NS);

async function sendToMode(toKey: string, rawName?: string) {
  try { decodeShareKey(toKey, SET); }
  catch { await appMsg(["This link is invalid or incomplete. Ask for a fresh one."], ERR); return; }
  const name = (rawName || "").trim().slice(0, 60);
  // The name comes straight from the link (#name=), so it's unverified. Never assert it as the verified
  // recipient ("only Mom can open it"). State what's cryptographically true (only the link's keyholder can
  // open it) and nudge the sender to confirm the link's provenance for anything sensitive.
  const segs: Seg[] = [
    { t: name ? `Send a file to “${name}”.` : "Send a secure file.", b: true },
    " Drop a file anywhere, or use the buttons below. It's encrypted in your browser so only the owner of this link's key can open it. No account or app needed.",
  ];
  if (name) segs.push(` “${name}” is just the label on this link, so if you're sending anything sensitive, confirm the link really came from them.`);
  await appMsg(segs);
  const drop = $("drop_container");
  drop.style.display = "flex";
  const dropLabel = drop.querySelector(".file_title") as HTMLElement | null;
  if (dropLabel) dropLabel.textContent = "Drop a file to send";
  marchingBorder(drop);
  const fileInput = $("file_input") as HTMLInputElement;
  const folderInput = $("folder_input") as HTMLInputElement;
  $("choose_file").addEventListener("click", () => fileInput.click());
  $("choose_folder").addEventListener("click", () => folderInput.click());
  drop.addEventListener("click", (e) => { if (!(e.target as HTMLElement).closest(".dc_btn, input")) fileInput.click(); });
  fileInput.addEventListener("change", () => { if (fileInput.files?.length) void handleSendTo(collectFromInput(fileInput.files), toKey, name); fileInput.value = ""; });
  folderInput.addEventListener("change", () => { if (folderInput.files?.length) void handleSendTo(collectFromInput(folderInput.files), toKey, name); folderInput.value = ""; });
  const dragWin = $("drag_window"), fdz = $("file_drag_zone");
  let depth = 0;
  window.addEventListener("dragenter", (e) => { e.preventDefault(); if (++depth === 1) { dragWin.style.display = "block"; fdz.style.display = "block"; } });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("dragleave", (e) => { e.preventDefault(); if (--depth <= 0) { depth = 0; dragWin.style.display = "none"; fdz.style.display = "none"; } });
  window.addEventListener("drop", (e) => { e.preventDefault(); depth = 0; dragWin.style.display = "none"; fdz.style.display = "none"; const dt = (e as DragEvent).dataTransfer; if (dt) void collectFromDrop(dt).then((items) => handleSendTo(items, toKey, name)); });
}

// Encrypt whatever the sender dropped to the link owner, with a fresh throwaway sender. No auth and no
// address-book write — an anonymous sender has neither. The zip phase (folders / multiple files) gets its
// own progress + cancel + error handling for big folders (mirrors encryptBundle); the encrypt phase is
// handled by encryptForRecipient.
async function handleSendTo(items: BundleItem[], toKey: string, name: string) {
  if (!items.length) return;
  const sender = await deriveThrowawayIdentity();
  // Don't pass the link's (unverified) name as the recipient label: the post-encrypt confirmation would
  // otherwise read 'encrypted for "<attacker-chosen name>"'. Anonymous senders have no contacts, so this
  // falls back to the neutral "for your recipient". (`name` is still shown, framed as a claim, in sendToMode.)
  const opts = { sender, remember: false };
  if (items.length === 1 && !items[0]!.fromFolder) {
    const f = items[0]!.file;
    uploadCard(f.name, "File", false);
    await encryptForRecipient(toKey, { plaintext: f, name: f.name, mime: f.type || "application/octet-stream" }, opts);
    return;
  }
  const base = uniqueBundleName(bundleName(items));
  uploadCard(base, `${items.length} ${items.length === 1 ? "file" : "files"}`, false);
  const total = items.reduce((n, it) => n + it.file.size, 0);
  const st = total >= STREAM_THRESHOLD ? new StatusMsg(true) : null; // big folders: progress + cancel during zip
  let zipBlob: Blob;
  try {
    st?.enableCancel();
    zipBlob = await zipBundleToBlob(items, st ? (b) => st.progress(b, total) : undefined, () => st?.cancelled ?? false);
  } catch (e) {
    console.error("FileKey: send-to bundling failed —", e); st?.fail();
    await appMsg(["Couldn't prepare those files. Please try again."], ERR); return;
  }
  if (st?.cancelled) { st.fail(); return; }
  st?.done();
  await encryptForRecipient(toKey, { plaintext: zipBlob, name: `${base}.zip`, mime: "application/zip" }, opts);
}

// ---- share key (v1 displayPublicKey) ----
async function displayPublicKey() {
  if (!(await ensureAuthed())) return;
  const sk = encodeShareKey(identity!.staticPkRaw, NS); // SPEC-DELTA: bech32 fkey1…, not v1's raw hex
  // ONE message (v1 displayPublicKey): intro text (typed) + key (word_broken) + Copy button.
  const msg = appShell();
  const intro = document.createElement("span"); msg.appendChild(intro);
  await typeInto(intro, "Your share key is a public key that allows others to encrypt data that only you can decrypt:", 8);
  const p = document.createElement("p"); p.textContent = sk; // monospace inset "code block" so the wrap reads as intentional
  p.style.cssText = "font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;line-height:1.6;word-break:break-all;background:var(--fk-fill);border-radius:10px;padding:14px 16px;margin:12px 0 0;color:var(--fk-ink-soft)";
  msg.appendChild(p);
  const copy = document.createElement("div"); copy.className = "copy_button no_select"; copy.style.marginTop = "14px";
  copy.innerHTML = `${SVG.copy.replace("<svg", '<svg class="copy_icon"')}<span class="cp_lbl">Copy</span>`;
  msg.appendChild(copy); scrollToBottom();
  copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(sk); const l = copy.querySelector(".cp_lbl")!; l.textContent = "Copied!"; setTimeout(() => (l.textContent = "Copy"), 1000); } catch {} });
}

// ---- "receive a file" link (owner side of the send-me-a-file flow) ----
// Wraps the owner's share key in a "#to=" link anyone can open to send them an encrypted file.
async function showSendLink() {
  if (!(await ensureAuthed())) return;
  const link = `${location.origin}/#to=${encodeShareKey(identity!.staticPkRaw, NS)}`;
  const msg = appShell();
  const intro = document.createElement("span"); msg.appendChild(intro);
  await typeInto(intro, "Share this link and anyone can send you an encrypted file, even if they don't have FileKey. Only you can open what they send:", 8);
  const p = document.createElement("p"); p.textContent = link;
  p.style.cssText = "font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;line-height:1.6;word-break:break-all;background:var(--fk-fill);border-radius:10px;padding:14px 16px;margin:12px 0 0;color:var(--fk-ink-soft)";
  msg.appendChild(p);
  const acts = document.createElement("div"); acts.style.cssText = "display:flex;gap:18px;margin-top:14px;flex-wrap:wrap";
  const mk = (label: string, icon: string, iconCls: string) => { const s = document.createElement("span"); s.className = "dl_action no_select"; s.innerHTML = `${icon.replace("<svg", `<svg class="${iconCls}"`)}<span class="lbl">${esc(label)}</span>`; return s; };
  const copyBtn = mk("Copy", SVG.copy, "copy_icon"); acts.appendChild(copyBtn);
  const shareBtn = typeof navigator.share === "function" ? mk("Share", SVG.share, "dl_icon") : null;
  if (shareBtn) acts.appendChild(shareBtn);
  const qrBtn = mk("Show QR", SVG.qr, "qr_icon"); acts.appendChild(qrBtn);
  msg.appendChild(acts);
  const qrBox = document.createElement("div"); qrBox.style.marginTop = "14px"; msg.appendChild(qrBox);
  scrollToBottom();
  copyBtn.addEventListener("click", async () => { try { await navigator.clipboard.writeText(link); const l = copyBtn.querySelector(".lbl")!; l.textContent = "Copied!"; setTimeout(() => (l.textContent = "Copy"), 1200); } catch {} });
  shareBtn?.addEventListener("click", async () => { try { await navigator.share({ url: link, title: "Send me a file securely with FileKey" }); } catch {} });
  qrBtn.addEventListener("click", () => {
    if (qrBox.childNodes.length) { qrBox.replaceChildren(); qrBtn.querySelector(".lbl")!.textContent = "Show QR"; return; } // toggle off
    const qr = qrcode(0, "M"); qr.addData(link); qr.make();
    qrBox.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true }); // QR encodes the link as modules, not HTML — safe
    const svg = qrBox.querySelector("svg");
    if (svg) svg.setAttribute("style", "width:180px;height:180px;background:#fff;border-radius:10px;padding:10px;box-sizing:border-box"); // white quiet zone so it scans + shows in dark mode
    qrBtn.querySelector(".lbl")!.textContent = "Hide QR";
  });
}

// ---- recovery (SPEC-DELTA §4.6: BIP39 / Bech32m, gated) ----
async function showRecovery() {
  if (!(await ensureAuthed())) return;
  flagSet(RECOVERY_ACK_KEY); // engaging with recovery → suppress the post-lock nudge
  await appMsg(["A recovery code is the only way to access your data if you lose your passkey. ", { link: "Show it", onClick: () => void revealRecovery() }, "."]);
}
async function revealRecovery() {
  // Re-verify with the passkey before revealing the recovery code (a bearer secret), and derive
  // master_prk on demand instead of keeping it resident in the Identity between uses.
  let masterPrk: Uint8Array;
  try {
    const prf = await getPrfSecret();
    masterPrk = masterPrkFromPrfSecret(prf);
    prf.fill(0); // scrub the PRF secret as soon as master_prk is derived
  }
  catch { await appMsg(["Passkey check cancelled, so the recovery code wasn't shown."], ERR); return; }
  const bip39 = encodeRecoveryBip39(masterPrk);
  masterPrk.fill(0); // the BIP39 string now carries the code for display; drop the raw master-PRK bytes
  // Same mono-inset format as the share key, but word-break:normal so the phrase wraps at spaces (whole words).
  const msg = appShell();
  const intro = document.createElement("span"); msg.appendChild(intro);
  await typeInto(intro, "Your recovery code. Keep it safe, since anyone who has it can open your files:", 8);
  const p = document.createElement("p"); p.textContent = bip39;
  p.style.cssText = "font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;line-height:1.7;word-break:normal;overflow-wrap:break-word;background:var(--fk-fill);border-radius:10px;padding:14px 16px;margin:12px 0 0;color:var(--fk-ink-soft)";
  msg.appendChild(p);
  const copy = document.createElement("div"); copy.className = "copy_button no_select"; copy.style.marginTop = "14px";
  copy.innerHTML = `${SVG.copy.replace("<svg", '<svg class="copy_icon"')}<span class="cp_lbl">Copy</span>`;
  msg.appendChild(copy);
  // Pair the code with the offline recovery tool (web/recover.html) — a download, not a nav link.
  const tool = document.createElement("p");
  tool.style.cssText = "margin:18px 0 0;font-size:14px;color:var(--fk-muted-2);line-height:1.55";
  tool.innerHTML = `Even if FileKey disappears, this code still works. Pair it with the <a class="msg_link" href="/recover.html" download="filekey-offline-recovery.html" style="font-weight:500;white-space:nowrap">${SVG.save.replace("<svg", '<svg style="width:12px;height:14px;fill:currentColor;vertical-align:-2px;margin-right:3px"')}offline recovery tool</a>, a single self-contained page that decrypts your files locally.`;
  msg.appendChild(tool);
  scrollToBottom();
  copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(bip39); const l = copy.querySelector(".cp_lbl")!; l.textContent = "Copied!"; setTimeout(() => (l.textContent = "Copy"), 1000); } catch {} });
}

// ---- contacts manager (menu → Contacts): list, rename, delete, clear-all; gated post-auth ----
async function showContacts() {
  if (!(await ensureAuthed())) return;
  const msg = appShell();
  const intro = document.createElement("span"); msg.appendChild(intro);
  await typeInto(intro, "Your contacts are saved on this device, encrypted with your passkey, never uploaded.", 8);
  const body = document.createElement("div"); body.className = "contacts_manager"; msg.appendChild(body);
  renderContacts(body); scrollToBottom();
}
function renderContacts(container: HTMLElement) {
  container.innerHTML = "";
  const list = Contacts.listContacts();
  if (!list.length) {
    container.insertAdjacentHTML("beforeend", `<p class="contacts_empty">No contacts yet. They're added automatically when you share a file with someone's share key, or add one manually below.</p>`);
  } else {
    const ul = document.createElement("div"); ul.className = "contacts_list";
    for (const c of list) {
      const row = document.createElement("div"); row.className = "contact_row";
      row.innerHTML = `<span class="contact_avatar">${esc(avatarInitial(c))}</span><div class="contact_main"><span class="contact_name">${esc(contactLabel(c))}</span><span class="contact_key">${esc(c.key)}</span></div><div class="contact_acts"><span class="contact_act rename_act no_select">Rename</span><span class="contact_act delete_act no_select">Delete</span></div>`;
      (row.querySelector(".rename_act") as HTMLElement).addEventListener("click", () => renameContact(row, c, container));
      (row.querySelector(".delete_act") as HTMLElement).addEventListener("click", async () => { await Contacts.removeContact(c.key); renderContacts(container); });
      ul.appendChild(row);
    }
    container.appendChild(ul);
  }
  // footer: Add contact + Import (always); Export + Clear all (only when there are contacts).
  const footer = document.createElement("div"); footer.className = "contacts_footer";
  const footAct = (cls: string, iconHtml: string, label: string, onClick: () => void) => {
    const s = document.createElement("span"); s.className = `${cls} no_select`;
    s.innerHTML = `${iconHtml}<span class="lbl">${esc(label)}</span>`;
    s.addEventListener("click", onClick); return s;
  };
  footer.appendChild(footAct("contacts_add", SVG.plus.replace("<svg", '<svg class="ca_icon" fill="currentColor"'), "Add", () => openAddForm(container)));
  footer.appendChild(footAct("contacts_add", SVG.import.replace("<svg", '<svg class="ca_icon"'), "Import", () => importContacts(container)));
  if (list.length) {
    footer.appendChild(footAct("contacts_add", SVG.export.replace("<svg", '<svg class="ca_icon"'), "Export", () => exportContacts()));
    const clear = document.createElement("span"); clear.className = "contacts_clear_link no_select";
    clear.innerHTML = `${SVG.trash.replace("<svg", '<svg class="ca_icon"')}<span class="lbl">Clear All</span>`;
    const lbl = clear.querySelector(".lbl") as HTMLElement;
    let arming = false;
    clear.addEventListener("click", async () => {
      if (!arming) { arming = true; lbl.textContent = "Clear all contacts? Tap again to confirm"; setTimeout(() => { if (arming) { arming = false; lbl.textContent = "Clear All"; } }, 3000); return; }
      await Contacts.clearContacts(); renderContacts(container);
    });
    footer.appendChild(clear);
  }
  container.appendChild(footer);
}

// Export the address book as a plain-JSON download. Share keys are public, so the file has no secrets —
// it just holds your contact list (names + their keys), so it imports fine onto a different passkey/device.
function exportContacts() {
  void saveBlob(new Blob([Contacts.exportContactsJson()], { type: "application/json" }), "filekey-contacts.json");
}

// Import contacts from a previously-exported JSON file: validate each share key (namespace-aware), dedupe
// against what's already saved, then report how many were added / skipped / rejected.
function importContacts(container: HTMLElement) {
  const input = document.createElement("input");
  input.type = "file"; input.accept = "application/json,.json"; input.style.display = "none";
  input.addEventListener("change", async () => {
    const file = input.files?.[0];
    input.remove();
    if (!file) return;
    let result;
    try {
      const text = await file.text();
      result = await Contacts.importContactsJson(text, (k) => { try { decodeShareKey(k, SET); return true; } catch { return false; } });
    } catch {
      await appMsg(["That doesn't look like a FileKey contacts file."], { speed: 8 });
      return;
    }
    renderContacts(container);
    const bits = [`Imported ${result.added} contact${result.added === 1 ? "" : "s"}`];
    if (result.skipped) bits.push(`${result.skipped} already saved`);
    if (result.rejected) bits.push(`${result.rejected} invalid`);
    await appMsg([`${bits.join(" · ")}.`], { speed: 4 });
  });
  document.body.appendChild(input);
  input.click();
}
// Manually add a contact (paste a share key + optional nickname), independent of sharing a file.
function openAddForm(container: HTMLElement) {
  container.querySelector(".contacts_footer")?.remove();
  container.querySelector(".add_contact_form")?.remove();
  const form = document.createElement("div"); form.className = "add_contact_form";
  form.innerHTML = `<textarea class="pub_key_textarea add_key_input" placeholder="Paste the recipient's share key" rows="1" spellcheck="false" autocapitalize="off" autocorrect="off" autocomplete="off"></textarea><input class="nickname_input add_nick_input" type="text" placeholder="Nickname (optional)" maxlength="40" autocomplete="off"><div class="pub_key_actions"><span class="confirm_pub_key no_select add_save">${SVG.check.replace("<svg", '<svg class="confirm_icon"')} <span>Save</span></span><span class="cancel_pub_key no_select add_cancel">${SVG.close.replace("<svg", '<svg class="cancel_icon"')} <span>Cancel</span></span></div>`;
  container.appendChild(form);
  const keyInput = form.querySelector(".add_key_input") as HTMLTextAreaElement;
  const nickInput = form.querySelector(".add_nick_input") as HTMLInputElement;
  const grow = () => { keyInput.style.height = "auto"; keyInput.style.height = keyInput.scrollHeight + "px"; };
  keyInput.addEventListener("input", grow); grow(); keyInput.focus({ preventScroll: true });
  const save = async () => {
    const key = keyInput.value.trim();
    if (!key) { keyInput.focus(); return; }
    try { decodeShareKey(key, SET); } catch { await appMsg(["That doesn't look like a valid FileKey share key."], { speed: 8 }); return; }
    const res = await Contacts.addContact(key, nickInput.value);
    if (!res.ok) {
      await appMsg([res.reason === "duplicate_key"
        ? `You've already saved this key${res.conflict.nickname ? ` as "${res.conflict.nickname}"` : ""}.`
        : `"${nickInput.value.trim()}" is already used by ${contactLabel(res.conflict)}. Try a different name.`], { speed: 6 });
      return;
    }
    renderContacts(container);
    await appMsg([`Added ${contactLabel(res.contact)} to your contacts.`], { speed: 4 });
  };
  (form.querySelector(".add_save") as HTMLElement).addEventListener("click", () => void save());
  (form.querySelector(".add_cancel") as HTMLElement).addEventListener("click", () => renderContacts(container));
  // Bring the form into view in place (it lives inside the contacts manager, which may be mid-stream) —
  // not the page bottom, which would scroll the user away from the form they just opened.
  form.scrollIntoView({ behavior: "smooth", block: "center" });
}
function renameContact(row: HTMLElement, c: Contacts.Contact, container: HTMLElement) {
  const main = row.querySelector(".contact_main") as HTMLElement;
  const acts = row.querySelector(".contact_acts") as HTMLElement;
  main.innerHTML = `<input class="nickname_input rename_input" type="text" maxlength="40" placeholder="Nickname" autocomplete="off"><span class="contact_key">${esc(c.key)}</span>`;
  acts.innerHTML = `<span class="contact_act save_rename no_select">Save</span><span class="contact_act cancel_rename no_select">Cancel</span>`;
  const input = main.querySelector(".rename_input") as HTMLInputElement;
  input.value = c.nickname || ""; input.focus();
  const save = async () => {
    const res = await Contacts.setNickname(c.key, input.value);
    if (!res.ok) { input.style.borderColor = "var(--fk-error)"; input.title = `Already used by ${contactLabel(res.conflict)}`; return; }
    renderContacts(container);
  };
  (acts.querySelector(".save_rename") as HTMLElement).addEventListener("click", () => void save());
  (acts.querySelector(".cancel_rename") as HTMLElement).addEventListener("click", () => renderContacts(container));
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); void save(); } else if (e.key === "Escape") renderContacts(container); });
}

// ---- requirements panel (v1 displayRequirements) ----
async function displayRequirements() {
  await appMsg([{ html: `<h3 class="msg_number_heading msg_no_margin_cont">FileKey needs a passkey with PRF</h3><p>FileKey unlocks your files using your passkey's PRF capability, which your current browser or device doesn't support yet. It works with:</p><ul><li><span>A recent iPhone or Mac: Safari 18+ or Chrome (iOS 18.4+ / macOS 15+), with an iCloud Keychain passkey</span></li><li><span>Android: Chrome with a Google Password Manager passkey</span></li><li><span>Windows 11 (25H2 or newer, fully updated): recent Chrome, Edge, or Firefox</span></li><li><span>A hardware security key (e.g. YubiKey) on a desktop browser</span></li></ul><p>Updating your browser and OS usually fixes it.</p>` }], { speed: 16 });
}

// ---- hamburger ("chiz") menu: verbatim v1 content ----
const CHIZ: Record<string, { speed: number; html: string }> = {
  chiz_terms: { speed: 10, html: `<h2 class=msg_menu_heading>Terms of Service</h2><ol><li><h3 class=msg_number_heading>Acceptance of Terms</h3><span>By using FileKey, you agree to these Terms of Service. If you do not agree, please do not use our site or services.</span></li><li><h3 class=msg_number_heading>Intended Use</h3><span>FileKey is designed to help you encrypt and decrypt files locally with your own hardware. You are responsible for using FileKey in compliance with all applicable laws and regulations.</span></li><li><h3 class=msg_number_heading>No Guarantees</h3><span>We provide FileKey "as is", without warranties of any kind. We do not guarantee that FileKey will be error-free, secure, or meet all your needs.</span></li><li><h3 class=msg_number_heading>Your Responsibility</h3><span>You must ensure that your hardware security key and devices remain secure. We are not responsible for lost keys, corrupted files, or unauthorized access resulting from your own actions.</span></li><li><h3 class=msg_number_heading>Liability Limitations</h3><span>To the fullest extent allowed by law, we will not be liable for any direct, indirect, incidental, or consequential damages arising from your use of-or inability to use-FileKey.</span></li><li><h3 class=msg_number_heading>No Third-Party Services</h3><span>FileKey does not rely on external services or third parties. You are solely responsible for managing your keys and files.</span></li><li><h3 class=msg_number_heading>Changes to Terms</h3><span>If we update these Terms of Service, we will post the changes here. Your continued use of FileKey after changes means you accept the updated terms.</span></li><li><h3 class=msg_number_heading>Contact Us</h3><span>If you have questions or concerns, please email us at contact@filekey.app.</span><br /><span>By using FileKey, you acknowledge and agree to these Terms of Service.</span></li></ol>` },
  chiz_privacy: { speed: 10, html: `<h2 class=msg_menu_heading>Privacy Policy</h2><h3 class=msg_number_heading>No Data Collection:</h3><span>We do not collect, store, or process any personal information on the website: no names, emails, or accounts. We do not track you, and we do not use analytics.</span><h3 class=msg_number_heading>Local-Only File Handling:</h3><span>All file encryption and decryption happens entirely on your device. We never send your files or keys to our servers. You remain in full control of your data at all times.</span><h3 class=msg_number_heading>Local Storage:</h3><span>We may use local storage on your device to remember your settings or key references. This information never leaves your device.</span><h3 class=msg_number_heading>No Third Parties:</h3><span>We do not share any data with third parties. There are no hidden integrations or external services.</span><h3 class=msg_number_heading>Changes to This Policy:</h3><span>If we make changes, we will update this page. Your continued use of FileKey means you accept the updated terms.</span><h3 class=msg_number_heading>Contact Us:</h3><span>If you have questions or concerns, please email us at contact@filekey.app.</span><br /><span>By using FileKey, you agree to this policy.</span>` },
  chiz_license: { speed: 16, html: `<h2 class=msg_menu_heading>License</h2><p>FileKey version 1 is released under the GNU General Public License v3.0 (GPLv3).</p><p>This means that you are free to use, modify, and distribute FileKey under the terms of the GPLv3 license. However, any modifications or derivative works must also be released under the same open-source license.</p><p><span>You can read the </span><a class=msg_link href=https://www.gnu.org/licenses/gpl-3.0.en.html target=_blank rel="noopener noreferrer">full license text here.${EXT_ICON}</a></p><p>By using FileKey, you agree to the terms of this license. If you contribute to the project, you also acknowledge that your contributions will be made available under GPLv3.</p>` },
  chiz_contact: { speed: 12, html: `<h2 class=msg_menu_heading>Contact Us</h2><p>You can email us at <a class=msg_link href="mailto:contact@filekey.app">contact@filekey.app</a>, or join our <a class=msg_link href="https://signal.group/#CjQKIDpdakX0nr1V00ciNv3dsWCFZgUwm_NylulFJz4VOUJ_EhBtY-bq759RNExzcCWMUGIB" target=_blank rel="noopener noreferrer">Signal group</a> to chat.</p>` },
};

function initChiz() {
  $("chiz_icon_container").innerHTML = `<span class="chiz_bar chiz_bar_top"></span><span class="chiz_bar chiz_bar_mid"></span><span class="chiz_bar chiz_bar_bot"></span>`;
  const backdrop = $("chiz_hidden_click_container");
  // Two dropdowns share one backdrop; only one is open at a time.
  const menu = $("chiz_menu_container"), icon = $("chiz_icon_container");        // About (hamburger)
  const acctMenu = $("acct_menu_container"), acctIcon = $("acct_icon_container"); // Your FileKey (sliders)
  const set = (m: HTMLElement, i: HTMLElement, on: boolean) => { m.style.display = on ? "block" : "none"; i.classList.toggle("is-open", on); i.setAttribute("aria-expanded", String(on)); };
  const close = () => { set(menu, icon, false); set(acctMenu, acctIcon, false); backdrop.style.display = "none"; };
  const openAbout = () => { close(); set(menu, icon, true); backdrop.style.display = "block"; };
  const openAcct = () => { close(); set(acctMenu, acctIcon, true); backdrop.style.display = "block"; };
  const toggleAbout = () => (menu.style.display === "block" ? close() : openAbout());
  const toggleAcct = () => (acctMenu.style.display === "block" ? close() : openAcct());
  icon.addEventListener("click", toggleAbout);
  icon.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleAbout(); } });
  acctIcon.addEventListener("click", toggleAcct);
  acctIcon.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleAcct(); } });
  backdrop.addEventListener("click", close);
  $("chiz_sendlink").addEventListener("click", () => { close(); void showSendLink(); });
  $("chiz_get_public_key").addEventListener("click", () => { close(); void displayPublicKey(); });
  $("chiz_contacts").addEventListener("click", () => { close(); void showContacts(); });
  $("chiz_recovery").addEventListener("click", () => { close(); void showRecovery(); });
  // Appearance: Light / Dark / Auto. "auto" follows the OS (prefers-color-scheme) and updates live.
  // Default (nothing saved) is auto, following the OS. Choice persists; the menu stays open so the change is visible.
  const themeMql = window.matchMedia("(prefers-color-scheme: dark)");
  // In-memory mode is the source of truth (seeded from storage); persistence is best-effort, so
  // Auto keeps following the OS live even if localStorage writes are blocked (private mode etc.).
  let themeMode = ((): string => { try { return localStorage.getItem("filekey-theme") || "auto"; } catch { return "auto"; } })();
  const themeOpts = Array.from(document.querySelectorAll<HTMLElement>(".theme_opt"));
  const resolveTheme = (mode: string): "light" | "dark" =>
    mode === "dark" || (mode === "auto" && themeMql.matches) ? "dark" : "light";
  const applyTheme = (mode: string) => {
    themeMode = mode;
    const resolved = resolveTheme(mode);
    document.documentElement.dataset.theme = resolved;
    const meta = document.querySelector('meta[name="theme-color"]') as HTMLMetaElement | null;
    if (meta) meta.content = resolved === "dark" ? "#0c0c0e" : "#ffffff";
    themeOpts.forEach((el) => { const on = el.dataset.mode === mode; el.classList.toggle("active", on); el.setAttribute("aria-checked", String(on)); });
  };
  const selectTheme = (el: HTMLElement) => {
    const mode = el.dataset.mode || "light";
    try { localStorage.setItem("filekey-theme", mode); } catch { /* storage blocked → in-memory only this session */ }
    applyTheme(mode);
  };
  applyTheme(themeMode);
  themeOpts.forEach((el, i) => {
    el.addEventListener("click", () => selectTheme(el));
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectTheme(el); }
      else if (e.key === "ArrowRight" || e.key === "ArrowDown") { e.preventDefault(); const n = themeOpts[(i + 1) % themeOpts.length]!; n.focus(); selectTheme(n); }
      else if (e.key === "ArrowLeft" || e.key === "ArrowUp") { e.preventDefault(); const p = themeOpts[(i - 1 + themeOpts.length) % themeOpts.length]!; p.focus(); selectTheme(p); }
    });
  });
  themeMql.addEventListener("change", () => { if (themeMode === "auto") applyTheme("auto"); });
  for (const id of Object.keys(CHIZ)) $(id).addEventListener("click", () => { close(); void appMsg([{ html: CHIZ[id]!.html }], { speed: CHIZ[id]!.speed }); });
  // external links: add the outbound ↗ icon + close the menu on click (v1/beta structure)
  document.querySelectorAll(".plain_menu_link").forEach((a) => { a.insertAdjacentHTML("beforeend", `<span class="chiz_outbound_link_stub"> ${SVG.outbound} </span>`); a.addEventListener("click", () => close()); });
}

// ---- intro (v1 initMessage) ----
// ---- update notice (a courtesy, NOT a security control) ----
// FileKey is served fresh on every reload (network-first SW + must-revalidate caching), so this does
// not gate updates; it just tells the user a newer build exists and shows what changed before they
// reload into it. version.json is the single source for the user-facing version: imported above as
// APP_VERSION (the version this bundle shipped as) and re-fetched here to spot a newer deploy.
let updatePrompted = false;
type Releases = Record<string, { date?: string; notes?: string[] }>;
// Friendly date from an ISO "YYYY-MM-DD" string, parsed by hand to avoid Date()/timezone drift.
function fmtReleaseDate(iso?: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso ?? "");
  if (!m) return iso ?? "";
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${months[Number(m[2]) - 1] ?? ""} ${Number(m[3])}, ${m[1] ?? ""}`;
}
// The full changelog: every release, newest first, as a typed chat panel (the Terms/Privacy menu idiom).
// Reached from the update notice's Changelog action.
async function showChangelog(releases: Releases | undefined): Promise<void> {
  const entries = Object.entries(releases ?? {})
    .map(([v, r]) => ({ v, date: r?.date, notes: (r?.notes ?? []).filter(Boolean) }))
    .sort((a, b) => (b.date ?? "").localeCompare(a.date ?? "")); // reverse chronological by date
  const body = entries.length
    ? entries.map((e) =>
        `<h3 class="msg_number_heading">FileKey ${esc(e.v)}${e.date ? ` · ${esc(fmtReleaseDate(e.date))}` : ""}</h3>` +
        `<ul class="update_notes">${e.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>`,
      ).join("")
    : "<span>No changelog available.</span>";
  await appMsg([{ html: `<h2 class="msg_menu_heading">Changelog</h2>${body}` }], { speed: 24 });
}
async function checkForUpdate() {
  if (updatePrompted) return;
  let latest: { current?: string; releases?: Releases } | undefined;
  try {
    const r = await fetch("/version.json", { cache: "no-store" });
    if (r.ok) latest = await r.json();
  } catch { /* offline or unreachable — nothing to do */ }
  if (!latest?.current || latest.current === APP_VERSION) return;
  updatePrompted = true;
  const version = latest.current;
  const releases = latest.releases;
  // Keep the notice itself a single line; the detail lives behind the Changelog action.
  const m = await appMsg(
    [{ html: `<b>FileKey ${esc(version)} is available.</b>` }],
    { dp: "warning_dp", icon: "warning_filekey_icon" },
  );
  // Size the stroke glyphs inline (no fill, so they stay line art) and space them from the label,
  // matching the recipient-prompt Confirm/Cancel chips (the .cancel_icon 18px sizer).
  const chipIcon = (svg: string) => svg.replace("<svg", '<svg style="width:18px;height:18px;margin-right:4px;flex:none"');
  actionRow(m, [
    { label: "Update", icon: chipIcon(SVG.download), onClick: () => location.reload() },
    { label: "Changelog", icon: chipIcon(SVG.doc), muted: true, onClick: () => void showChangelog(releases) },
    { label: "Later", icon: chipIcon(SVG.clock), muted: true, onClick: () => m.querySelector(".msg_actions")?.remove() },
  ]);
}

async function intro() {
  await appMsg([
    { t: "Files need protection. FileKey secures them", b: true },
    ". Works with passkeys. Drop files in. They lock. Drop them again. They unlock. Your data stays on your device, and only you hold the key. Open source and powered by AES-256 encryption, the same standard trusted by the US government for top-secret information.",
    " For the latest updates, join our ",
    { html: extLink("https://signal.group/#CjQKIDpdakX0nr1V00ciNv3dsWCFZgUwm_NylulFJz4VOUJ_EhBtY-bq759RNExzcCWMUGIB", "Signal") },
    " group or ",
    { html: extLinkDot("https://filekey.substack.com/", "Substack") },
  ], { speed: 12 });
  const m = await appMsg(["To start, unlock your existing filekey or create a new one."]);
  buttonRow(m, [
    { label: "Unlock", icon: SVG.fingerprint.replace("<svg", '<svg class="fp_icon"'), onClick: () => void loadSecKey() },
    { label: "Create", ghost: true, icon: SVG.plus.replace("<svg", '<svg class="plus_icon"'), onClick: () => void genNewPasskey() },
  ]);
}

// ---- marching-ants dashed border on the drop zone (v1 createAnimatedBorder) ----
function marchingBorder(el: HTMLElement) {
  const NS_SVG = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS_SVG, "svg");
  Object.assign(svg.style, { position: "absolute", inset: "0", width: "100%", height: "100%", pointerEvents: "none", overflow: "visible" } as CSSStyleDeclaration);
  const rect = document.createElementNS(NS_SVG, "rect");
  rect.setAttribute("x", "1"); rect.setAttribute("y", "1"); rect.setAttribute("rx", "14"); rect.setAttribute("fill", "none");
  rect.setAttribute("stroke", "#1377f980"); rect.setAttribute("stroke-width", "2"); rect.setAttribute("stroke-dasharray", "3 6"); rect.setAttribute("stroke-linecap", "round");
  svg.appendChild(rect); el.prepend(svg);
  const size = () => { const w = el.clientWidth - 2, h = el.clientHeight - 2; if (w > 0 && h > 0) { rect.setAttribute("width", String(w)); rect.setAttribute("height", String(h)); } }; // guard: drop zone is display:none until auth (clientWidth 0)
  new ResizeObserver(size).observe(el); size();
  if (!REDUCED) { let off = 0; const step = () => { off = (off - 0.25) % 9; rect.setAttribute("stroke-dashoffset", String(off)); requestAnimationFrame(step); }; step(); }
}

// ---- init ----
function init() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {}); // PWA: installable + offline
  mainInner = $("main_inner");
  $("logo_bar").innerHTML = `${SVG.logo.replace("<svg", '<svg class="filekey_logo_icon"')}<span id="logo_txt">FileKey</span>`;
  $("logo_bar").addEventListener("click", () => location.reload());
  const dc = document.querySelector(".dc_icon_container") as HTMLElement; // v1: class not id
  dc.innerHTML = SVG.plus; setIcon(dc, "plus_icon");
  initChiz();
  $("version_number_ele").textContent = "v" + APP_VERSION;

  // "Send me a file" link: a #to=<share key> visitor encrypts to the owner anonymously (throwaway
  // sender) — no passkey, so it bypasses the WebAuthn gate. It still needs a secure context (Web Crypto).
  const sendTo = parseSendToHash();
  if (sendTo) {
    if (!checkSupport().secureContext) { void appMsg(["FileKey needs a secure context (HTTPS or localhost)."], ERR); return; }
    void sendToMode(sendTo.to, sendTo.name);
    return;
  }

  const support = checkSupport();
  if (!support.secureContext || !support.webauthn) { void appMsg([support.secureContext ? "This browser doesn't support WebAuthn passkeys, which FileKey requires." : "FileKey needs a secure context (HTTPS or localhost)."], ERR); return; }

  const fileInput = $("file_input") as HTMLInputElement;
  const folderInput = $("folder_input") as HTMLInputElement;
  // Two explicit pickers (one input can't be both multi-file and webkitdirectory); the zone itself is the drop target.
  $("choose_file").addEventListener("click", () => fileInput.click());
  $("choose_folder").addEventListener("click", () => folderInput.click());
  // Clicking the zone itself (background, not a control) opens the file picker — the primary action.
  // Ignore .dc_btn and the hidden inputs: input.click() dispatches a *bubbling* click that would
  // otherwise re-enter this handler and open a second (file) picker behind the folder picker.
  $("drop_container").addEventListener("click", (e) => { if (!(e.target as HTMLElement).closest(".dc_btn, input")) fileInput.click(); });
  fileInput.addEventListener("change", () => { if (fileInput.files?.length) void handleItems(collectFromInput(fileInput.files)); fileInput.value = ""; });
  folderInput.addEventListener("change", () => { if (folderInput.files?.length) void handleItems(collectFromInput(folderInput.files)); folderInput.value = ""; });
  marchingBorder($("drop_container"));

  const dragWin = $("drag_window"), fdz = $("file_drag_zone");
  let depth = 0;
  window.addEventListener("dragenter", (e) => { e.preventDefault(); if (++depth === 1 && identity) { dragWin.style.display = "block"; fdz.style.display = "block"; } });
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("dragleave", (e) => { e.preventDefault(); if (--depth <= 0) { depth = 0; dragWin.style.display = "none"; fdz.style.display = "none"; } });
  window.addEventListener("drop", (e) => { e.preventDefault(); depth = 0; dragWin.style.display = "none"; fdz.style.display = "none"; const dt = (e as DragEvent).dataTransfer; if (dt) void collectFromDrop(dt).then(handleItems); });

  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") void checkForUpdate(); });
  void intro().finally(() => { allowAutoScroll = true; void checkForUpdate(); });
}
init();
