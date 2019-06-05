<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Content\Business\KeyProvider;

use Spryker\Zed\Content\Business\Exception\ContentKeyNotCreatedException;
use Spryker\Zed\Content\Dependency\Service\ContentToUtilUuidGeneratorServiceInterface;
use Spryker\Zed\Content\Persistence\ContentRepositoryInterface;

/**
 * This file is part of the Spryker Suite.
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */
class ContentKeyProvider implements ContentKeyProviderInterface
{
    protected const KEY_GENERATOR_STEPS_LIMIT = 10;
    protected const ERROR_CONTENT_KEY_NOT_CREATED = 'Cannot create content key: reached limit of the generation operations.';

    /**
     * @var \Spryker\Zed\Content\Dependency\Service\ContentToUtilUuidGeneratorServiceInterface
     */
    protected $utilUuidGeneratorService;

    /**
     * @var \Spryker\Zed\Content\Persistence\ContentRepositoryInterface
     */
    protected $contentRepository;

    /**
     * @param \Spryker\Zed\Content\Dependency\Service\ContentToUtilUuidGeneratorServiceInterface $utilUuidGeneratorService
     * @param \Spryker\Zed\Content\Persistence\ContentRepositoryInterface $contentRepository
     */
    public function __construct(
        ContentToUtilUuidGeneratorServiceInterface $utilUuidGeneratorService,
        ContentRepositoryInterface $contentRepository
    ) {
        $this->utilUuidGeneratorService = $utilUuidGeneratorService;
        $this->contentRepository = $contentRepository;
    }

    /**
     * @throws \Spryker\Zed\Content\Business\Exception\ContentKeyNotCreatedException
     *
     * @return string
     */
    public function generateContentKey(): string
    {
        $index = 0;

        do {
            if ($index >= static::KEY_GENERATOR_STEPS_LIMIT) {
                throw new ContentKeyNotCreatedException(static::ERROR_CONTENT_KEY_NOT_CREATED);
            }

            $candidate = $this->utilUuidGeneratorService->generateUuid5FromObjectId(
                sprintf("%s-%d", microtime(true), ++$index)
            );
        } while ($this->contentRepository->hasKey($candidate));

        return $candidate;
    }

    /**
     * @param int $idContent
     *
     * @return string
     */
    public function getContentKeyByIdContent(int $idContent): string
    {
        $contentTransfer = $this->contentRepository->findContentById($idContent);

        return $contentTransfer->getKey();
    }
}
