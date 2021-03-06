// Copyright 2021 The Cockroach Authors.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

import { FixLong } from "src/util";

export const longToInt = (value: number | Long) => Number(FixLong(value));

export const limitText = (text: string, limit: number): string => {
  return text.length > limit ? text.slice(0, limit - 3).concat("...") : text;
};
