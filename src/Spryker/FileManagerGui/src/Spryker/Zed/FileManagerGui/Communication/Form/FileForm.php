<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\FileManagerGui\Communication\Form;

use Generated\Shared\Transfer\FileTransfer;
use Spryker\Shared\FileManagerGui\FileManagerGuiConstants;
use Spryker\Zed\Kernel\Communication\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\CollectionType;
use Symfony\Component\Form\Extension\Core\Type\FileType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\File;

/**
 * @method \Spryker\Zed\FileManagerGui\Communication\FileManagerGuiCommunicationFactory getFactory()
 * @method \Spryker\Zed\FileManagerGui\FileManagerGuiConfig getConfig()
 */
class FileForm extends AbstractType
{
    const FIELD_FILE_NAME = 'fileName';
    const FIELD_FILE_CONTENT = 'fileContent';
    const FIELD_ID_FILE = 'idFile';
    const FIELD_USE_REAL_NAME = 'useRealName';
    const FILE_LOCALIZED_ATTRIBUTES = 'fileLocalizedAttributes';

    const OPTION_DATA_CLASS = 'data_class';
    const OPTION_AVAILABLE_LOCALES = 'option_available_locales';

    /**
     * @return string
     */
    public function getName()
    {
        return 'file';
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this
            ->addFileNameField($builder)
            ->addIdFileField($builder)
            ->addUseRealNameOption($builder)
            ->addFileLocalizedAttributesForm($builder, $options)
            ->addFileContentField($builder);
    }

    /**
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver
     *
     * @return void
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setRequired(static::OPTION_AVAILABLE_LOCALES);

        $resolver->setDefaults([
            static::OPTION_DATA_CLASS => FileTransfer::class,
        ]);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addFileNameField(FormBuilderInterface $builder)
    {
        $formData = $builder->getData();
        $builder->add(static::FIELD_FILE_NAME, TextType::class, [
            'required' => !empty($formData[static::FIELD_USE_REAL_NAME]),
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addIdFileField(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_ID_FILE, HiddenType::class);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addFileContentField(FormBuilderInterface $builder)
    {
        $formData = $builder->getData();
        $builder->add(static::FIELD_FILE_CONTENT, FileType::class, [
            'required' => empty($formData[static::FIELD_ID_FILE]),
            'constraints' => [
                new File([
                    'maxSize' => $this->getConfig()->getMaxSize(),
                    'mimeTypes' => $this->getConfig()->getAllowedMimeTypes(),
                    'mimeTypesMessage' => FileManagerGuiConstants::ERROR_MIME_TYPE_MESSAGE,
                ]),
            ],
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addUseRealNameOption(FormBuilderInterface $builder)
    {
        $formData = $builder->getData();

        if (empty($formData[static::FIELD_ID_FILE])) {
            $builder->add(static::FIELD_USE_REAL_NAME, CheckboxType::class, [
                'attr' => [
                    'checked' => 'checked',
                ],
                'required' => false,
            ]);
        }

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array|null $options
     *
     * @return $this
     */
    protected function addFileLocalizedAttributesForm(FormBuilderInterface $builder, array $options = null)
    {
        $builder->add(static::FILE_LOCALIZED_ATTRIBUTES, CollectionType::class, [
            'entry_type' => FileLocalizedAttributesForm::class,
            'allow_add' => true,
            'allow_delete' => true,

            'entry_options' => [
                static::OPTION_AVAILABLE_LOCALES => $options[static::OPTION_AVAILABLE_LOCALES],
            ],
        ]);

        return $this;
    }
}
