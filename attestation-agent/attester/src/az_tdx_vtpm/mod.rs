// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use az_tdx_vtpm::vtpm::Quote as TpmQuote;
use az_tdx_vtpm::{hcl, imds, is_tdx_cvm, vtpm};
use log::debug;
use serde::{Deserialize, Serialize};
use std::result::Result::Ok;

pub fn detect_platform() -> bool {
    match is_tdx_cvm() {
        Ok(tdx) => tdx,
        Err(err) => {
            debug!("Failed to retrieve HCL report from TPM: {err}");
            false
        }
    }
}

#[derive(Debug, Default)]
pub struct AzTdxVtpmAttester;

#[derive(Serialize, Deserialize)]
struct Evidence {
    tpm_quote: TpmQuote,
    hcl_report: Vec<u8>,
    tdx_quote: Vec<u8>,
}

#[async_trait::async_trait]
impl Attester for AzTdxVtpmAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<String> {
        let hcl_report_bytes = vtpm::get_report()?;
        let hcl_report = hcl::HclReport::new(hcl_report_bytes.clone())?;
        let tdx_report_slice = hcl_report.tdx_report_slice();
        let report_body = imds::ReportBody::new(tdx_report_slice);
        let tdx_quote_bytes = imds::get_td_quote(report_body)?;

        let tpm_quote = vtpm::get_quote(&report_data)?;

        let evidence = Evidence {
            tpm_quote,
            hcl_report: hcl_report_bytes,
            tdx_quote: tdx_quote_bytes,
        };
        Ok(serde_json::to_string(&evidence)?)
    }
}
