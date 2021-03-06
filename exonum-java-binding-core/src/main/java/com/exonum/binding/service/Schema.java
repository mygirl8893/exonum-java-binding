/*
 * Copyright 2018 The Exonum Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.exonum.binding.service;

import com.exonum.binding.common.hash.HashCode;
import java.util.List;

/**
 * A schema of the tables (= indices) of a service.
 */
public interface Schema {

  /**
   * Returns the root hashes of Merklized tables in this database schema, as of the current
   * state of the database. If there are no Merklized tables, returns an empty list.
   */
  List<HashCode> getStateHashes();
}
