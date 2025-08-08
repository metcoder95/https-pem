/// <reference types="node" />
import { SelfsignedOptions, CertificateField } from 'selfsigned';

type CertificateAttribute = CertificateField;

type HttpsPEMGenerateOpts = {
  attr?: CertificateAttribute[];
  opts?: SelfsignedOptions;
};
type HttpsPEMGenerateResult = {
  key: string;
  cert: string;
};

type HttpsPEM = {
  key: string | null;
  cert: string | null;
  generate(config?: HttpsPEMGenerateOpts): Promise<HttpsPEMGenerateResult>;
  generate(
    config: HttpsPEMGenerateOpts | null,
    done: (err: Error | null, result: HttpsPEMGenerateResult) => void
  ): void;
};

export default HttpsPEM;
export declare const key: HttpsPEM['key'];
export declare const cert: HttpsPEM['cert'];
export declare const generate: HttpsPEM['generate'];

export {
  SelfsignedOptions,
  CertificateAttribute,
  HttpsPEMGenerateResult,
  HttpsPEMGenerateOpts,
};
