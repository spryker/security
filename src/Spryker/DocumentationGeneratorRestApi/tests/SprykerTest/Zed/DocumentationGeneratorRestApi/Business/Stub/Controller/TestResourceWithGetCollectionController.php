<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\DocumentationGeneratorRestApi\Business\Stub\Controller;

class TestResourceWithGetCollectionController
{
    /**
     * @Glue({
     *     "getCollection": {
     *          "summary": [
     *              "Summary example"
     *          ],
     *          "headers": [
     *              "Accept-Language"
     *          ],
     *          "responses": {
     *              "400": "Bad Request",
     *              "404": "Item not found"
     *          }
     *     }
     * })
     *
     * @return void
     */
    public function getAction()
    {
    }
}
