import 'src/aead_integration.dart';
import 'src/aes_integration.dart';
import 'src/stream_integration.dart';

Future<void> main() async {
  runAesIntegration();
  await runStreamIntegration();
  runAeadIntegration();
  print('integration_consumer: all checks passed');
}
