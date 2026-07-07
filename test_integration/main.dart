import 'src/aead_integration.dart';
import 'src/aes_integration.dart';
import 'src/block_cipher_integration.dart';
import 'src/mlkem_integration.dart';
import 'src/stream_integration.dart';

Future<void> main() async {
  runAesIntegration();
  runBlockCipherIntegration();
  runAeadIntegration();
  runStreamIntegration();
  runMlkemIntegration();
  print('integration_consumer: all checks passed');
}
