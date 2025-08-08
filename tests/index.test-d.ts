import { expectAssignable } from 'tsd';

import {
  generate,
  key,
  cert,
  HttpsPEMGenerateResult,
  HttpsPEMGenerateOpts,
} from '..';

expectAssignable<string | null>(key);
expectAssignable<string | null>(cert);
expectAssignable<Promise<HttpsPEMGenerateResult>>(generate({}));
expectAssignable<void>(generate({}, () => {}));
expectAssignable<void>(generate(null, () => {}));
expectAssignable<HttpsPEMGenerateOpts>({
  attr: [{ name: 'hello', value: 'world' }],
  opts: { keySize: 1234 },
});
