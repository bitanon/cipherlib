// Test vectors by Eric Young, taken from the Blowfish page by Bruce Schneier:
// https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt

// ignore_for_file: non_constant_identifier_names

/// ECB test data (key, clear text, cipher text)
final blowfish_ecb_vectors = [
  {
    "key": "0000000000000000",
    "plain": "0000000000000000",
    "cipher": "4EF997456198DD78",
  },
  {
    "key": "FFFFFFFFFFFFFFFF",
    "plain": "FFFFFFFFFFFFFFFF",
    "cipher": "51866FD5B85ECB8A",
  },
  {
    "key": "3000000000000000",
    "plain": "1000000000000001",
    "cipher": "7D856F9A613063F2",
  },
  {
    "key": "1111111111111111",
    "plain": "1111111111111111",
    "cipher": "2466DD878B963C9D",
  },
  {
    "key": "0123456789ABCDEF",
    "plain": "1111111111111111",
    "cipher": "61F9C3802281B096",
  },
  {
    "key": "1111111111111111",
    "plain": "0123456789ABCDEF",
    "cipher": "7D0CC630AFDA1EC7",
  },
  {
    "key": "0000000000000000",
    "plain": "0000000000000000",
    "cipher": "4EF997456198DD78",
  },
  {
    "key": "FEDCBA9876543210",
    "plain": "0123456789ABCDEF",
    "cipher": "0ACEAB0FC6A0A28D",
  },
  {
    "key": "7CA110454A1A6E57",
    "plain": "01A1D6D039776742",
    "cipher": "59C68245EB05282B",
  },
  {
    "key": "0131D9619DC1376E",
    "plain": "5CD54CA83DEF57DA",
    "cipher": "B1B8CC0B250F09A0",
  },
  {
    "key": "07A1133E4A0B2686",
    "plain": "0248D43806F67172",
    "cipher": "1730E5778BEA1DA4",
  },
  {
    "key": "3849674C2602319E",
    "plain": "51454B582DDF440A",
    "cipher": "A25E7856CF2651EB",
  },
  {
    "key": "04B915BA43FEB5B6",
    "plain": "42FD443059577FA2",
    "cipher": "353882B109CE8F1A",
  },
  {
    "key": "0113B970FD34F2CE",
    "plain": "059B5E0851CF143A",
    "cipher": "48F4D0884C379918",
  },
  {
    "key": "0170F175468FB5E6",
    "plain": "0756D8E0774761D2",
    "cipher": "432193B78951FC98",
  },
  {
    "key": "43297FAD38E373FE",
    "plain": "762514B829BF486A",
    "cipher": "13F04154D69D1AE5",
  },
  {
    "key": "07A7137045DA2A16",
    "plain": "3BDD119049372802",
    "cipher": "2EEDDA93FFD39C79",
  },
  {
    "key": "04689104C2FD3B2F",
    "plain": "26955F6835AF609A",
    "cipher": "D887E0393C2DA6E3",
  },
  {
    "key": "37D06BB516CB7546",
    "plain": "164D5E404F275232",
    "cipher": "5F99D04F5B163969",
  },
  {
    "key": "1F08260D1AC2465E",
    "plain": "6B056E18759F5CCA",
    "cipher": "4A057A3B24D3977B",
  },
  {
    "key": "584023641ABA6176",
    "plain": "004BD6EF09176062",
    "cipher": "452031C1E4FADA8E",
  },
  {
    "key": "025816164629B007",
    "plain": "480D39006EE762F2",
    "cipher": "7555AE39F59B87BD",
  },
  {
    "key": "49793EBC79B3258F",
    "plain": "437540C8698F3CFA",
    "cipher": "53C55F9CB49FC019",
  },
  {
    "key": "4FB05E1515AB73A7",
    "plain": "072D43A077075292",
    "cipher": "7A8E7BFA937E89A3",
  },
  {
    "key": "49E95D6D4CA229BF",
    "plain": "02FE55778117F12A",
    "cipher": "CF9C5D7A4986ADB5",
  },
  {
    "key": "018310DC409B26D6",
    "plain": "1D9D5C5018F728C2",
    "cipher": "D1ABB290658BC778",
  },
  {
    "key": "1C587F1C13924FEF",
    "plain": "305532286D6F295A",
    "cipher": "55CB3774D13EF201",
  },
  {
    "key": "0101010101010101",
    "plain": "0123456789ABCDEF",
    "cipher": "FA34EC4847B268B2",
  },
  {
    "key": "1F1F1F1F0E0E0E0E",
    "plain": "0123456789ABCDEF",
    "cipher": "A790795108EA3CAE",
  },
  {
    "key": "E0FEE0FEF1FEF1FE",
    "plain": "0123456789ABCDEF",
    "cipher": "C39E072D9FAC631D",
  },
  {
    "key": "0000000000000000",
    "plain": "FFFFFFFFFFFFFFFF",
    "cipher": "014933E0CDAFF6E4",
  },
  {
    "key": "FFFFFFFFFFFFFFFF",
    "plain": "0000000000000000",
    "cipher": "F21E9A77B71C49BC",
  },
  {
    "key": "0123456789ABCDEF",
    "plain": "0000000000000000",
    "cipher": "245946885754369A",
  },
  {
    "key": "FEDCBA9876543210",
    "plain": "FFFFFFFFFFFFFFFF",
    "cipher": "6B5C5A9C5D9E0A5A",
  },
];

/// set_key test data: variable length keys with a fixed plain text
final blowfish_setkey_plain = "FEDCBA9876543210";

/// set_key test data (key, cipher text) for keys of 1 to 24 bytes
final blowfish_setkey_vectors = [
  {"key": "F0", "cipher": "F9AD597C49DB005E"},
  {"key": "F0E1", "cipher": "E91D21C1D961A6D6"},
  {"key": "F0E1D2", "cipher": "E9C2B70A1BC65CF3"},
  {"key": "F0E1D2C3", "cipher": "BE1E639408640F05"},
  {"key": "F0E1D2C3B4", "cipher": "B39E44481BDB1E6E"},
  {"key": "F0E1D2C3B4A5", "cipher": "9457AA83B1928C0D"},
  {"key": "F0E1D2C3B4A596", "cipher": "8BB77032F960629D"},
  {"key": "F0E1D2C3B4A59687", "cipher": "E87A244E2CC85E82"},
  {"key": "F0E1D2C3B4A5968778", "cipher": "15750E7A4F4EC577"},
  {"key": "F0E1D2C3B4A596877869", "cipher": "122BA70B3AB64AE0"},
  {"key": "F0E1D2C3B4A5968778695A", "cipher": "3A833C9AFFC537F6"},
  {"key": "F0E1D2C3B4A5968778695A4B", "cipher": "9409DA87A90F6BF2"},
  {"key": "F0E1D2C3B4A5968778695A4B3C", "cipher": "884F80625060B8B4"},
  {"key": "F0E1D2C3B4A5968778695A4B3C2D", "cipher": "1F85031C19E11968"},
  {"key": "F0E1D2C3B4A5968778695A4B3C2D1E", "cipher": "79D9373A714CA34F"},
  {"key": "F0E1D2C3B4A5968778695A4B3C2D1E0F", "cipher": "93142887EE3BE15C"},
  {"key": "F0E1D2C3B4A5968778695A4B3C2D1E0F00", "cipher": "03429E838CE2D14B"},
  {
    "key": "F0E1D2C3B4A5968778695A4B3C2D1E0F0011",
    "cipher": "A4299E27469FF67B",
  },
  {
    "key": "F0E1D2C3B4A5968778695A4B3C2D1E0F001122",
    "cipher": "AFD5AED1C1BC96A8",
  },
  {
    "key": "F0E1D2C3B4A5968778695A4B3C2D1E0F00112233",
    "cipher": "10851C0E3858DA9F",
  },
  {
    "key": "F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344",
    "cipher": "E6F51ED79B9DB21F",
  },
  {
    "key": "F0E1D2C3B4A5968778695A4B3C2D1E0F001122334455",
    "cipher": "64A6E14AFD36B46F",
  },
  {
    "key": "F0E1D2C3B4A5968778695A4B3C2D1E0F00112233445566",
    "cipher": "80C7D7D45A5479AD",
  },
  {
    "key": "F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344556677",
    "cipher": "05044B62FA52D080",
  },
];
