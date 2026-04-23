import 'src/aead_integration.dart';
import 'src/aes_integration.dart';
import 'src/stream_integration.dart';

Future<void> main() async {
  runAesIntegration();
  runAeadIntegration();
  runStreamIntegration();
  print('integration_consumer: all checks passed');
}
