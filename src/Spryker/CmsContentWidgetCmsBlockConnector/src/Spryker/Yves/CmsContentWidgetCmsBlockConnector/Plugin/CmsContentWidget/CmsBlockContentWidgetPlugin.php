<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\CmsContentWidgetCmsBlockConnector\Plugin\CmsContentWidget;

use ArrayObject;
use DateTime;
use Generated\Shared\Transfer\CmsBlockTransfer;
use Spryker\Shared\CmsContentWidget\Dependency\CmsContentWidgetConfigurationProviderInterface;
use Spryker\Yves\CmsContentWidget\Dependency\CmsContentWidgetPluginInterface;
use Spryker\Yves\Kernel\AbstractPlugin;
use Twig_Environment;

/**
 * @method \Spryker\Yves\CmsContentWidgetCmsBlockConnector\CmsContentWidgetCmsBlockConnectorFactory getFactory()
 */
class CmsBlockContentWidgetPlugin extends AbstractPlugin implements CmsContentWidgetPluginInterface
{
    /**
     * @var \Spryker\Shared\CmsContentWidget\Dependency\CmsContentWidgetConfigurationProviderInterface
     */
    protected $widgetConfiguration;

    /**
     * @var string
     */
    protected $localeName;

    /**
     * @var string
     */
    protected $storeName;

    /**
     * @param \Spryker\Shared\CmsContentWidget\Dependency\CmsContentWidgetConfigurationProviderInterface $widgetConfiguration
     */
    public function __construct(CmsContentWidgetConfigurationProviderInterface $widgetConfiguration)
    {
        $this->widgetConfiguration = $widgetConfiguration;
        $this->localeName = $this->getLocale();
        $this->storeName = $this->getApplication()['store'];
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return callable
     */
    public function getContentWidgetFunction()
    {
        return [$this, 'contentWidgetFunction'];
    }

    /**
     * @param \Twig_Environment $twig
     * @param array $context
     * @param array|string $blockNames
     * @param string|null $templateIdentifier
     *
     * @return string
     */
    public function contentWidgetFunction(Twig_Environment $twig, array $context, $blockNames, $templateIdentifier = null): string
    {
        $blocks = $this->getBlockDataByNames($blockNames);
        $templatePath = $this->resolveTemplatePath($templateIdentifier);
        $rendered = '';

        foreach ($blocks as $block) {
            $blockData = $this->getCmsBlockTransfer($block);

            $isActive = $this->validateBlock($blockData) && $this->validateDates($blockData);

            if ($isActive) {
                $rendered .= $twig->render($templatePath, [
                    'placeholders' => $this->getPlaceholders($blockData->getSpyCmsBlockGlossaryKeyMappings()),
                    'cmsContent' => $blockData,
                ]);
            }
        }

        return $rendered;
    }

    /**
     * @param string|null $templateIdentifier
     *
     * @return string
     */
    protected function resolveTemplatePath(?string $templateIdentifier = null): string
    {
        if (!$templateIdentifier) {
            $templateIdentifier = CmsContentWidgetConfigurationProviderInterface::DEFAULT_TEMPLATE_IDENTIFIER;
        }

        return $this->widgetConfiguration->getAvailableTemplates()[$templateIdentifier];
    }

    /**
     * @param string[] $blockNames
     *
     * @return array
     */
    protected function getBlockDataByNames($blockNames): array
    {
        $blocks = $this->getFactory()
            ->getCmsBlockStorageClient()
            ->findBlocksByNames($blockNames, $this->localeName, $this->storeName);

        return $blocks;
    }

    /**
     * @param \Generated\Shared\Transfer\CmsBlockTransfer $cmsBlockData
     *
     * @return bool
     */
    protected function validateBlock(CmsBlockTransfer $cmsBlockData): bool
    {
        return $cmsBlockData->getTemplateName() !== null;
    }

    /**
     * @param \Generated\Shared\Transfer\CmsBlockTransfer $cmsBlockTransfer
     *
     * @return bool
     */
    protected function validateDates(CmsBlockTransfer $cmsBlockTransfer): bool
    {
        $dateToCompare = new DateTime();

        if ($cmsBlockTransfer->getValidFrom() !== null) {
            $validFrom = new DateTime($cmsBlockTransfer->getValidFrom());

            if ($dateToCompare < $validFrom) {
                return false;
            }
        }

        if ($cmsBlockTransfer->getValidTo() !== null) {
            $validTo = new DateTime($cmsBlockTransfer->getValidTo());

            if ($dateToCompare > $validTo) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param \ArrayObject $mappings
     *
     * @return array
     */
    protected function getPlaceholders(ArrayObject $mappings): array
    {
        $placeholders = [];
        foreach ($mappings as $mapping) {
            $placeholders[$mapping->getPlaceholder()] = $mapping->getGlossaryKey()->getKey();
        }

        return $placeholders;
    }

    /**
     * @param array $data
     *
     * @return \Generated\Shared\Transfer\CmsBlockTransfer
     */
    protected function getCmsBlockTransfer(array $data): CmsBlockTransfer
    {
        return (new CmsBlockTransfer())->fromArray($data, true);
    }
}
